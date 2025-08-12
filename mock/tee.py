from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple
import ssl
import os

def _load_testdata() -> Tuple[str, Dict[str, Any], Dict[str, Any], Dict[str, Any], List[Any], List[Any], Dict[str, Any]]:

    base = os.environ.get("TESTDATA_DIR")
    if base is None:
        here = os.path.dirname(os.path.abspath(__file__))
        base = os.path.join(here, "tests", "testdata")

    def load_json(rel_path: str) -> Any:
        path = os.path.join(base, rel_path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def load_text(rel_path: str) -> str:
        path = os.path.join(base, rel_path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return ""

    chain_id_str = load_text(os.path.join("rpc", "chain_id.txt")) or "1"
    try:
        chain_id_hex = hex(int(chain_id_str, 0))
    except Exception:
        chain_id_hex = "0x1"
    block = load_json(os.path.join("rpc", "block.json")) or {}
    transaction = load_json(os.path.join("rpc", "transaction.json")) or {}
    receipt = load_json(os.path.join("rpc", "receipt.json")) or {}
    receipts = load_json(os.path.join("rpc", "receipts.json")) or []
    logs = load_json(os.path.join("rpc", "logs.json")) or []
    account = load_json(os.path.join("rpc", "account.json")) or {}
    return chain_id_hex, block, transaction, receipt, receipts, logs, account

_CHAIN_ID_HEX, _BLOCK_DATA, _TX_DATA, _TX_RECEIPT, _BLOCK_RECEIPTS, _LOGS, _ACCOUNT_DATA = _load_testdata()



def hex_pad(num: int, size: int = 64) -> str:
    return "0x" + f"{num:x}".rjust(size, "0")


class JSONRPCHandler(BaseHTTPRequestHandler):

    # Hardcode dummy block 
    DUMMY_BLOCK = {
        "number": "0x0",  
        "hash": hex_pad(0),
        "parentHash": hex_pad(0),
        "nonce": "0x0",
        "sha3Uncles": hex_pad(0),
        "logsBloom": hex_pad(0, 512),
        "transactionsRoot": hex_pad(0),
        "stateRoot": hex_pad(0),
        "receiptsRoot": hex_pad(0),
        "miner": hex_pad(0, 40),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "size": "0x0",
        "extraData": "0x",
        "gasLimit": "0x0",
        "gasUsed": "0x0",
        "timestamp": "0x0",
        "transactions": [],
        "uncles": [],
    }
    def handle_block_number(self, params: List[Any]) -> str:
        num_hex = _BLOCK_DATA.get("number")
        if isinstance(num_hex, str):
            return num_hex
        return "0x0"

    def handle_get_block_transaction_count_by_hash(self, params: List[Any]) -> str:
        txs = _BLOCK_DATA.get("transactions")
        if isinstance(txs, list):
            return hex(len(txs))
        return "0x0"

    def handle_get_block_transaction_count_by_number(self, params: List[Any]) -> str:
        txs = _BLOCK_DATA.get("transactions")
        if isinstance(txs, list):
            return hex(len(txs))
        return "0x0"

    def handle_get_transaction_by_hash(self, params: List[Any]) -> Optional[Dict[str, Any]]:
        return _TX_DATA or None

    def handle_get_transaction_by_block_hash_and_index(self, params: List[Any]) -> Optional[Dict[str, Any]]:
        return _TX_DATA or None

    def handle_get_transaction_by_block_number_and_index(self, params: List[Any]) -> Optional[Dict[str, Any]]:
        return _TX_DATA or None

    def handle_get_balance(self, params: List[Any]) -> str:
        bal = _ACCOUNT_DATA.get("account", {}).get("balance")
        if isinstance(bal, str) and bal.startswith("0x"):
            return bal
        return "0x0"

    def handle_get_transaction_count(self, params: List[Any]) -> str:
        nonce = _ACCOUNT_DATA.get("account", {}).get("nonce")
        if isinstance(nonce, str) and nonce.startswith("0x"):
            return nonce
        return "0x0"

    def handle_gas_price(self, params: List[Any]) -> str:
        return "0x3b9aca00"  # 1 gwei in hex

    def handle_max_priority_fee_per_gas(self, params: List[Any]) -> str:
        return "0x1dcd6500"  # 0.5 gwei in hex

    def handle_blob_base_fee(self, params: List[Any]) -> str:
        return "0x0"

    def handle_call(self, params: List[Any]) -> str:
        return "0x0"

    def handle_get_storage_at(self, params: List[Any]) -> str:
        return "0x0"

    def _send_json(self, payload: Dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:  
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            self.send_error(411, "Missing Content-Length header")
            return
        try:
            length = int(content_length)
        except ValueError:
            self.send_error(400, "Invalid Content-Length header")
            return
        body = self.rfile.read(length)
        try:
            request_json = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON payload")
            return
        if isinstance(request_json, list):
            responses = [self._handle_request(obj) for obj in request_json]
            self._send_json(responses)
        else:
            response = self._handle_request(request_json)
            self._send_json(response)

    def _handle_request(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        jsonrpc = obj.get("jsonrpc")
        req_id = obj.get("id")
        method = obj.get("method")
        params = obj.get("params", [])
        if jsonrpc != "2.0" or not isinstance(method, str):
            return self._error_response(req_id, -32600, "Invalid Request")
        try:
            result = self._dispatch_method(method, params)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except JSONRPCError as err:
            return self._error_response(req_id, err.code, err.message)
        except Exception as exc:  
            return self._error_response(req_id, -32603, f"Internal error: {exc}")

    def _error_response(self, req_id: Any, code: int, message: str) -> Dict[str, Any]:
        """Return a JSON‑RPC error response object."""
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    def _dispatch_method(self, method: str, params: Any) -> Any:
        if method == "eth_getProof":
            return self.handle_get_proof(params)
        if method == "eth_blockNumber":
            return self.handle_block_number(params)
        if method == "eth_getBlockByNumber":
            return self.handle_get_block_by_number(params)
        if method == "eth_getBlockByHash":
            return self.handle_get_block_by_hash(params)
        # Transaction retrieval
        if method == "eth_getTransactionByHash":
            return self.handle_get_transaction_by_hash(params)
        if method == "eth_getTransactionByBlockHashAndIndex":
            return self.handle_get_transaction_by_block_hash_and_index(params)
        if method == "eth_getTransactionByBlockNumberAndIndex":
            return self.handle_get_transaction_by_block_number_and_index(params)
        if method == "eth_getTransactionReceipt":
            return self.handle_get_transaction_receipt(params)
        if method == "eth_getBlockReceipts":
            return self.handle_get_block_receipts(params)
        if method == "eth_getLogs":
            return self.handle_get_logs(params)
        if method == "eth_getBalance":
            return self.handle_get_balance(params)
        if method == "eth_getTransactionCount":
            return self.handle_get_transaction_count(params)
        if method == "eth_getCode":
            return self.handle_get_code(params)
        if method == "eth_getBlockTransactionCountByHash":
            return self.handle_get_block_transaction_count_by_hash(params)
        if method == "eth_getBlockTransactionCountByNumber":
            return self.handle_get_block_transaction_count_by_number(params)
        if method == "eth_gasPrice":
            return self.handle_gas_price(params)
        if method == "eth_maxPriorityFeePerGas":
            return self.handle_max_priority_fee_per_gas(params)
        if method == "eth_blobBaseFee":
            return self.handle_blob_base_fee(params)
        if method == "eth_call":
            return self.handle_call(params)
        if method == "eth_getStorageAt":
            return self.handle_get_storage_at(params)
        if method == "eth_chainId":
            return self.handle_chain_id(params)
        # Unknown/unimplemented method: return an None
        return None


    def handle_get_proof(self, params: List[Any]) -> Dict[str, Any]:
        if not params or len(params) < 2:
            raise JSONRPCError(-32602, "Invalid params for eth_getProof")
        address = params[0]
        storage_keys = params[1] if len(params) > 1 else []
        # Return a dummy EIP1186 proof. 
        return {
            "address": address,
            "balance": "0x0",
            "nonce": "0x0",
            "codeHash": hex_pad(0),
            "storageHash": hex_pad(0),
            "storageProof": [
                {
                    "key": key,
                    "value": "0x0",
                    "proof": [],
                }
                for key in storage_keys
            ],
        }

    def handle_get_block_by_number(self, params: List[Any]) -> Dict[str, Any]:
        if _BLOCK_DATA:
            return _BLOCK_DATA
        return self.DUMMY_BLOCK

    def handle_get_block_by_hash(self, params: List[Any]) -> Dict[str, Any]:
        if _BLOCK_DATA:
            return _BLOCK_DATA
        return self.DUMMY_BLOCK

    def handle_get_transaction_receipt(self, params: List[Any]) -> Optional[Dict[str, Any]]:
        if _TX_RECEIPT:
            return _TX_RECEIPT
        return None

    def handle_get_block_receipts(self, params: List[Any]) -> Optional[List[Dict[str, Any]]]:
        if isinstance(_BLOCK_RECEIPTS, list) and _BLOCK_RECEIPTS:
            return _BLOCK_RECEIPTS
        return []

    def handle_get_logs(self, params: List[Any]) -> List[Any]:
        if isinstance(_LOGS, list) and _LOGS:
            return _LOGS
        return []

    def handle_get_code(self, params: List[Any]) -> str:
        code = _ACCOUNT_DATA.get("code")
        if isinstance(code, str) and code.startswith("0x"):
            return code
        return "0x"

    def handle_chain_id(self, params: List[Any]) -> str:
        return _CHAIN_ID_HEX


class JSONRPCError(Exception):

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def run_server(host: str, port: int, cert: str | None = None, key: str | None = None) -> None:
    httpd = HTTPServer((host, port), JSONRPCHandler)
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"
    print(f"Mock TEE server listening on {scheme}://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()



def parse_args() -> tuple[str, int, str | None, str | None]:
    parser = argparse.ArgumentParser(description="Run a mock TEE JSON-RPC server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8545, help="Port to listen on")
    parser.add_argument("--cert", help="Path to TLS certificate (PEM)")
    parser.add_argument("--key", help="Path to TLS private key (PEM)")
    args = parser.parse_args()
    return args.host, args.port, args.cert, args.key



if __name__ == "__main__":
    host, port, cert, key = parse_args()
    run_server(host, port, cert, key)