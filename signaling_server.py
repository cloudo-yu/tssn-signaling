import os
import json
import time
import secrets
import asyncio
import websockets

# 記憶體狀態表 (僅處理控制平面信令，絕不經手備份資料，符合 FR-10 / Section 3.2)
CONNECTED_DEVICES = {}  # {device_id: websocket}
ENDPOINTS = {}          # {device_id: {"public": "ip:port", "local": "ip:port"}}
PAIRING_TOKENS = {}     # {token: {"source_id": str, "expires_at": float, "used": bool}}
PAIRS = {}              # {device_a: device_b, device_b: device_a}
FOLDER_STATUS = {}      # {device_id: {"locked": False, "quota_gb": 0.0, "folder_ready": False}}
PENDING_REVOKES = set() # 紀錄離線期間被撤銷信任的 device_id

# QR Code 一次性有效期限：10 分鐘 (600 秒) (符合 FR-02)
TOKEN_EXPIRY_SECONDS = 600


async def broadcast_pair_status(device_id: str):
    """向配對雙方廣播最新的在線綠燈狀態、P2P 端點與資料夾 Lock/容量狀態 (FR-03)"""
    peer_id = PAIRS.get(device_id)
    targets = [uid for uid in (device_id, peer_id) if uid]

    for uid in targets:
        ws = CONNECTED_DEVICES.get(uid)
        if not ws:
            continue
        pid = PAIRS.get(uid)
        try:
            await ws.send(json.dumps({
                "type": "status_update",
                "peer_id": pid,
                "self_online": uid in CONNECTED_DEVICES,
                "peer_online": (pid in CONNECTED_DEVICES) if pid else False,
                "peer_endpoints": ENDPOINTS.get(pid, {}) if pid else {},
                "peer_folder_status": FOLDER_STATUS.get(pid, {}) if pid else {}
            }))
        except Exception:
            pass


async def handle_client(websocket):
    device_id = None
    try:
        async for raw_msg in websocket:
            # 嚴格限制信令封包大小 (< 8KB)，確保伺服器絕不中繼任何備份檔案 (FR-10 / T12)
            if len(raw_msg) > 8192:
                await websocket.send(json.dumps({
                    "type": "error",
                    "reason": "Control plane only: message size exceeds limit."
                }))
                continue

            data = json.loads(raw_msg)
            action = data.get("action")

            # 1. 裝置啟動註冊：支援自動恢復「永久信任夥伴」與資料夾狀態
            if action == "register":
                device_id = data["device_id"]
                CONNECTED_DEVICES[device_id] = websocket
                ENDPOINTS[device_id] = {
                    "public": data.get("public_endpoint", ""),
                    "local": data.get("local_endpoint", "")
                }

                # 若該裝置在離線期間曾被對方刪除資料夾而撤銷信任，上線時立即通知清除憑證
                if device_id in PENDING_REVOKES:
                    PENDING_REVOKES.discard(device_id)
                    await websocket.send(json.dumps({
                        "type": "trust_revoked",
                        "reason": "對等端已刪除授權資料夾或重置配對，永久信任已終止，請重新掃描 QR Code！"
                    }))
                    continue

                # 恢復資料夾狀態 (若為 Point B 重開機)
                if "folder_status" in data and isinstance(data["folder_status"], dict):
                    FOLDER_STATUS[device_id] = data["folder_status"]

                # 無條件恢復永久信任配對關係 (不論對方此刻是否已在線)
                trusted_peer = data.get("trusted_peer_id")
                if trusted_peer:
                    PAIRS[device_id] = trusted_peer
                    PAIRS[trusted_peer] = device_id

                await websocket.send(json.dumps({
                    "type": "registered",
                    "device_id": device_id
                }))
                await broadcast_pair_status(device_id)

            # 2. Point A 產生一次性、10 分鐘有效的配對 QR Token (FR-02)
            elif action == "generate_qr_token":
                token = secrets.token_urlsafe(24)
                PAIRING_TOKENS[token] = {
                    "source_id": device_id,
                    "expires_at": time.time() + TOKEN_EXPIRY_SECONDS,
                    "used": False
                }
                await websocket.send(json.dumps({
                    "type": "qr_token_created",
                    "token": token,
                    "expires_in": TOKEN_EXPIRY_SECONDS
                }))

            # 3. Point B 掃描 QR Code 並檢查是否過期或重複使用 (FR-02, T03, T04)
            elif action == "scan_qr_token":
                token = data.get("token")
                info = PAIRING_TOKENS.get(token)

                if not info:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "無效的配對 QR Code Token。"}))
                elif info["used"]:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "此 QR Code 已被使用過 (僅限單次使用)。"}))
                elif time.time() > info["expires_at"]:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "此 QR Code 已超過 10 分鐘有效期限！"}))
                elif info["source_id"] == device_id:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "無法與自己的裝置配對。"}))
                else:
                    await websocket.send(json.dumps({
                        "type": "pairing_approval_required",
                        "token": token,
                        "source_id": info["source_id"]
                    }))

            # 4. Point B 明確同意配對：派發永久信任金鑰並建立雙向綁定 (FR-02, FR-06)
            elif action == "approve_pairing":
                token = data.get("token")
                info = PAIRING_TOKENS.get(token)
                if not info or info["used"] or time.time() > info["expires_at"]:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "QR Code 已過期或失效，請重新產生。"}))
                    continue

                info["used"] = True
                source_id = info["source_id"]
                target_id = device_id

                PENDING_REVOKES.discard(source_id)
                PENDING_REVOKES.discard(target_id)

                PAIRS[source_id] = target_id
                PAIRS[target_id] = source_id
                FOLDER_STATUS[target_id] = {"locked": False, "quota_gb": 0.0, "folder_ready": False}

                # 產生永久信任專屬的 P2P 通訊驗證金鑰 (由 A 與 B 儲存於本機)
                p2p_secret = secrets.token_hex(32)

                for uid, role, pid in [(source_id, "Point A", target_id), (target_id, "Point B", source_id)]:
                    ws = CONNECTED_DEVICES.get(uid)
                    if ws:
                        await ws.send(json.dumps({
                            "type": "pairing_success",
                            "role": role,
                            "peer_id": pid,
                            "peer_endpoints": ENDPOINTS.get(pid, {}),
                            "p2p_secret": p2p_secret
                        }))
                await broadcast_pair_status(target_id)

            # 5. Point B 即時同步資料夾 Lock/Unlock 與容量上限狀態
            elif action == "update_folder_status":
                if device_id:
                    FOLDER_STATUS[device_id] = {
                        "locked": bool(data.get("locked", False)),
                        "quota_gb": float(data.get("quota_gb", 0.0)),
                        "folder_ready": bool(data.get("folder_ready", False))
                    }
                    await broadcast_pair_status(device_id)

            # 6. 當授權資料夾被刪除或重置時，立即撤銷雙向永久信任，強制重掃 QR Code
            elif action == "revoke_trust":
                peer_id = PAIRS.pop(device_id, None)
                if peer_id:
                    PAIRS.pop(peer_id, None)
                FOLDER_STATUS.pop(device_id, None)
                if peer_id:
                    FOLDER_STATUS.pop(peer_id, None)

                reason = data.get("reason", "授權資料夾已被刪除，永久信任已撤銷，請重新使用 QR Code 配對！")
                for uid in (device_id, peer_id):
                    if not uid:
                        continue
                    ws = CONNECTED_DEVICES.get(uid)
                    if ws:
                        await ws.send(json.dumps({"type": "trust_revoked", "reason": reason}))
                    elif uid != device_id:
                        # 若對方目前離線，先記錄下來，等對方下次打開軟體時立即通知撤銷
                        PENDING_REVOKES.add(uid)

            # 7. 輕量級心跳訊息 (FR-03, FR-07)
            elif action == "heartbeat":
                await broadcast_pair_status(device_id)

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if device_id and CONNECTED_DEVICES.get(device_id) == websocket:
            del CONNECTED_DEVICES[device_id]
            await broadcast_pair_status(device_id)


async def main():
    port = int(os.environ.get("PORT", 8765))
    print(f"[Signaling Server] Listening on 0.0.0.0:{port}")
    async with websockets.serve(handle_client, "0.0.0.0", port):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())