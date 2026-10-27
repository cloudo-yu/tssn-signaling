import os
import json
import time
import secrets
import asyncio
import websockets

# 記憶體暫存表 (僅保留最小連線與配對中繼資料，符合 FR-10 與 Section 3.2)
CONNECTED_DEVICES = {}  # {device_id: websocket}
ENDPOINTS = {}          # {device_id: {"public": "ip:port", "local": "ip:port"}}
PAIRING_TOKENS = {}     # {token: {"source_id": str, "expires_at": float, "used": bool}}
PAIRS = {}              # {device_a: device_b, device_b: device_a}
FOLDER_STATUS = {}      # {device_b: {"locked": False, "quota_gb": 0.0, "folder_ready": False}}

TOKEN_EXPIRY_SECONDS = 120  # FR-02: QR Token 限時 120 秒有效，單次使用


async def broadcast_pair_status(device_id: str):
    """通知配對雙方彼此的最新在線狀態、P2P 端點與資料夾 Lock/Quota 狀態 (FR-03)"""
    peer_id = PAIRS.get(device_id)
    if not peer_id:
        return

    for uid, pid in [(device_id, peer_id), (peer_id, device_id)]:
        ws = CONNECTED_DEVICES.get(uid)
        if ws:
            try:
                await ws.send(json.dumps({
                    "type": "status_update",
                    "peer_id": pid,
                    "self_online": uid in CONNECTED_DEVICES,
                    "peer_online": pid in CONNECTED_DEVICES,
                    "peer_endpoints": ENDPOINTS.get(pid, {}),
                    "peer_folder_status": FOLDER_STATUS.get(pid, {})
                }))
            except Exception:
                pass


async def handle_client(websocket):
    device_id = None
    try:
        async for raw_msg in websocket:
            # 嚴格限制控制訊息大小 (< 8KB)，防止透過信令伺服器偷傳檔案 (FR-10 / T12)
            if len(raw_msg) > 8192:
                await websocket.send(json.dumps({
                    "type": "error",
                    "reason": "Control plane only: message exceeds signaling size limit."
                }))
                continue

            data = json.loads(raw_msg)
            action = data.get("action")

            # 1. 裝置註冊與紀錄 Cloudflare STUN 探測出的公網/區網端點
            if action == "register":
                device_id = data["device_id"]
                CONNECTED_DEVICES[device_id] = websocket
                ENDPOINTS[device_id] = {
                    "public": data.get("public_endpoint", ""),
                    "local": data.get("local_endpoint", "")
                }
                await websocket.send(json.dumps({
                    "type": "registered",
                    "device_id": device_id
                }))
                await broadcast_pair_status(device_id)

            # 2. Point A 申請產生一次性、具時效性的 QR 配對 Token (FR-02)
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

            # 3. Point B 掃描 QR Code 後驗證 Token 有效性 (FR-02, T03, T04)
            elif action == "scan_qr_token":
                token = data.get("token")
                info = PAIRING_TOKENS.get(token)

                if not info:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "無效的配對 QR Code Token。"}))
                elif info["used"]:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "此 QR Code 已被使用過 (Single-use limit)。"}))
                elif time.time() > info["expires_at"]:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "此 QR Code 已過期 (Expired)。"}))
                elif info["source_id"] == device_id:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "無法與自己的裝置進行配對。"}))
                else:
                    await websocket.send(json.dumps({
                        "type": "pairing_approval_required",
                        "token": token,
                        "source_id": info["source_id"]
                    }))

            # 4. Point B 明確同意配對，建立信任綁定並預設 Unlock (FR-02, FR-06)
            elif action == "approve_pairing":
                token = data.get("token")
                info = PAIRING_TOKENS.get(token)
                if not info or info["used"] or time.time() > info["expires_at"]:
                    await websocket.send(json.dumps({"type": "pairing_error", "reason": "配對授權逾時或 Token 已失效。"}))
                    continue

                info["used"] = True
                source_id = info["source_id"]
                PAIRS[source_id] = device_id
                PAIRS[device_id] = source_id
                FOLDER_STATUS[device_id] = {"locked": False, "quota_gb": 0.0, "folder_ready": False}

                # 產生該次信任配對專屬的 P2P 驗證金鑰 (FR-06)
                p2p_auth_secret = secrets.token_hex(32)

                for uid, role, pid in [(source_id, "Point A", device_id), (device_id, "Point B", source_id)]:
                    ws = CONNECTED_DEVICES.get(uid)
                    if ws:
                        await ws.send(json.dumps({
                            "type": "pairing_success",
                            "role": role,
                            "peer_id": pid,
                            "peer_endpoints": ENDPOINTS.get(pid, {}),
                            "p2p_secret": p2p_auth_secret
                        }))
                await broadcast_pair_status(device_id)

            # 5. Point B 更新資料夾 Lock/Unlock 與授權容量狀態
            elif action == "update_folder_status":
                FOLDER_STATUS[device_id] = {
                    "locked": bool(data.get("locked", False)),
                    "quota_gb": float(data.get("quota_gb", 0.0)),
                    "folder_ready": bool(data.get("folder_ready", False))
                }
                await broadcast_pair_status(device_id)

            # 6. 當授權資料夾被刪除時，立即撤銷雙向信任，強制重新掃描 QR Code
            elif action == "revoke_trust":
                peer_id = PAIRS.pop(device_id, None)
                if peer_id:
                    PAIRS.pop(peer_id, None)
                FOLDER_STATUS.pop(device_id, None)
                if peer_id:
                    FOLDER_STATUS.pop(peer_id, None)

                reason = data.get("reason", "授權資料夾已被刪除，信任關係已終止。")
                for uid in (device_id, peer_id):
                    ws = CONNECTED_DEVICES.get(uid)
                    if ws:
                        await ws.send(json.dumps({
                            "type": "trust_revoked",
                            "reason": reason
                        }))

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
    print(f"[Signaling Server] Control plane listening on 0.0.0.0:{port}")
    async with websockets.serve(handle_client, "0.0.0.0", port):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())