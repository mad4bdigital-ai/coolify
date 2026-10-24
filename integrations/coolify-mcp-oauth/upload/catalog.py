"""Approved MCP capability registry for upload sidecar.

Tools are registered once and discovered automatically. No arbitrary HTTP path
becomes an executable tool; new routes require explicit trusted registration.
"""
import transfer

def descriptors():
    tools={}
    for name in transfer.OPS:
        if name=="upload_file":props={"content_base64":{"type":"string"},"sha256":{"type":"string"}};required=["content_base64","sha256"]
        elif name=="upload_begin":props={"size":{"type":"integer"},"sha256":{"type":"string"}};required=["size","sha256"]
        elif name=="upload_chunk":props={"transfer_id":{"type":"string"},"offset":{"type":"integer"},"base64":{"type":"string"}};required=list(props)
        else:props={"transfer_id":{"type":"string"}};required=["transfer_id"]
        tools[name]={"name":name,"description":"Base64 JSON transport into quarantine only. Requires authorized file bytes; begin/status do not upload bytes. No ChatGPT file ID, local-path or file_uri reading.","inputSchema":{"type":"object","properties":props,"required":required,"additionalProperties":False}}
    tools["upload_attachment"]={"name":"upload_attachment","description":"Receive caller-supplied Base64 bytes into quarantine and verify SHA-256. Does NOT resolve ChatGPT attachment IDs, file_uri, or local paths. Requires files:upload; does not install or store on VPS.","inputSchema":{"type":"object","properties":{"content_base64":{"type":"string","description":"Base64-encoded attachment bytes (not a ChatGPT file ID)"},"sha256":{"type":"string","description":"SHA-256 digest of original attachment"},"filename":{"type":"string","description":"Original filename for audit only; does not select a path"}},"required":["content_base64","sha256","filename"],"additionalProperties":False}}
    tools["upload_server_file"]={"name":"upload_server_file","description":"Copy existing checksum-verified quarantine artifact to fixed VPS directory. Requires prior successful upload; does NOT install a plugin.","inputSchema":{"type":"object","properties":{"sha256":{"type":"string"},"filename":{"type":"string"}},"required":["sha256","filename"],"additionalProperties":False}}
    tools["upload_from_url"]={"name":"upload_from_url","description":"Fetch a URL only from server-configured approved HTTPS hosts into quarantine. Does NOT fetch private ChatGPT attachment URLs.","inputSchema":{"type":"object","properties":{"url":{"type":"string"},"sha256":{"type":"string"}},"required":["url","sha256"],"additionalProperties":False}}
    return tools

def list_tools():
    return list(descriptors().values())

def supported(name):
    return isinstance(name,str) and name in descriptors()
