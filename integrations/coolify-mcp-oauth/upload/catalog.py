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
    tools["upload_attachment"]={"name":"upload_attachment","description":"Receive a real attachment payload: either caller-supplied Base64 bytes or an actual allowlisted HTTPS download URL. Requires OAuth files:upload and SHA-256. ChatGPT file_id, file_uri, sandbox paths and local paths are NOT resolvable by this MCP tool; do not manufacture download links. Successful intake is quarantine only, not installation.","inputSchema":{"type":"object","properties":{"content_base64":{"type":"string","description":"Actual file bytes encoded as Base64 by an attachment-capable client"},"url":{"type":"string","description":"An actual authorized HTTPS downloadable URL, if supplied by the host; never infer from a file ID"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"filename":{"type":"string","description":"Filename for audit only, never used as filesystem path"}},"required":["sha256","filename"],"oneOf":[{"required":["content_base64"],"not":{"required":["url"]}},{"required":["url"],"not":{"required":["content_base64"]}}],"additionalProperties":False}}
    tools["upload_server_file"]={"name":"upload_server_file","description":"Copy existing checksum-verified quarantine artifact to fixed VPS directory. Requires prior successful upload; does NOT install a plugin.","inputSchema":{"type":"object","properties":{"sha256":{"type":"string"},"filename":{"type":"string"}},"required":["sha256","filename"],"additionalProperties":False}}
    tools["upload_from_url"]={"name":"upload_from_url","description":"Import a real, authorized HTTPS download URL into quarantine with SHA-256 verification. Assistant workflow: when an attachment is available, first obtain an actual downloadable HTTPS URL using an authorized attachment-capable source/tool; supply it here only if the URL exists, is accessible by this server, and its hostname is on the server allowlist. If no such URL exists, use an authorized direct-byte upload tool or report that transfer is blocked. NEVER invent or reconstruct a URL; sandbox:/ links, local filesystem paths, ChatGPT file IDs/file_uri, and private or expired signed links are NOT valid public download URLs. Result quarantined means neither delivered to VPS nor installed.","inputSchema":{"type":"object","properties":{"url":{"type":"string","description":"Actual HTTPS download URL from an explicitly authorized source, with hostname allowlisted by the server; not sandbox:/, local path, inferred URL, or ChatGPT file_uri."},"sha256":{"type":"string","description":"Expected lowercase SHA-256 of the complete original file; do not guess."}},"required":["url","sha256"],"additionalProperties":False}}
    return tools

def list_tools():
    return list(descriptors().values())

def supported(name):
    return isinstance(name,str) and name in descriptors()
