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
    tools["upload_from_url"]={"name":"upload_from_url","description":"Import a real, authorized HTTPS download URL into quarantine with SHA-256 verification. Assistant workflow: when an attachment is available, first obtain an actual downloadable HTTPS URL using an authorized attachment-capable source/tool; supply it here only if the URL exists, is accessible by this server, and its hostname is on the server allowlist. If no such URL exists, use an authorized direct-byte upload tool or report that transfer is blocked. NEVER invent or reconstruct a URL; sandbox:/ links, local filesystem paths, ChatGPT file IDs/file_uri, and private or expired signed links are NOT valid public download URLs. Result quarantined means neither delivered to VPS nor installed.","inputSchema":{"type":"object","properties":{"url":{"type":"string","description":"Actual HTTPS download URL from an explicitly authorized source, with hostname allowlisted by the server; not sandbox:/, local path, inferred URL, or ChatGPT file_uri."},"sha256":{"type":"string","description":"Expected lowercase SHA-256 of the complete original file; do not guess."}},"required":["url","sha256"],"additionalProperties":False}}
    tools["upload_from_reference"]={
        "name":"upload_from_reference",
        "description":"Import an opaque owner-bound reference previously staged by an authorized host attachment bridge. Requires pre-staged .bin and .json manifest in private inbox; does NOT fetch ChatGPT file IDs or access conversation files directly. Verifies principal, authorization status, size and SHA-256, and returns quarantined only.",
        "inputSchema":{"type":"object","properties":{
            "reference":{"type":"string","pattern":"^[a-f0-9]{32}$","description":"Opaque 32-hex handle issued by a trusted attachment bridge; NOT a ChatGPT file_id/file_uri or path"},
            "sha256":{"type":"string","pattern":"^[a-f0-9]{64}$","description":"Expected digest of original file"}
        },"required":["reference","sha256"],"additionalProperties":False}}
    return tools

def list_tools():
    return list(descriptors().values())

def supported(name):
    return isinstance(name,str) and name in descriptors()
