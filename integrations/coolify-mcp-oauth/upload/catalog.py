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
        tools[name]={"name":name,"description":"Authenticated quarantine file transfer","inputSchema":{"type":"object","properties":props,"required":required,"additionalProperties":False}}
    tools["upload_server_file"]={"name":"upload_server_file","description":"Promote checksum-verified quarantine artifact to fixed VPS directory","inputSchema":{"type":"object","properties":{"sha256":{"type":"string"},"filename":{"type":"string"}},"required":["sha256","filename"],"additionalProperties":False}}
    tools["upload_from_url"]={"name":"upload_from_url","description":"Import approved HTTPS URL into quarantine","inputSchema":{"type":"object","properties":{"url":{"type":"string"},"sha256":{"type":"string"}},"required":["url","sha256"],"additionalProperties":False}}
    return tools

def list_tools():
    return list(descriptors().values())

def supported(name):
    return isinstance(name,str) and name in descriptors()
