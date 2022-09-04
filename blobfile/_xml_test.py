import json
import time
from typing import Any, Dict, Optional
import xmltodict
from blobfile import _xml as xml

resp = """\
<?xml version="1.0" encoding="utf-8"?>  
<EnumerationResults ContainerName="https://myaccount.blob.core.windows.net/mycontainer">  
  <MaxResults>4</MaxResults>  
  <Blobs>  
    <Blob>  
      <Name>blob1.txt</Name>  
      <Url>https://myaccount.blob.core.windows.net/mycontainer/blob1.txt</Url>  
      <Properties>  
        <Last-Modified>Sun, 27 Sep 2009 18:41:57 GMT</Last-Modified>  
        <Etag>0x8CAE7D55D050B8B</Etag>  
        <Content-Length>8</Content-Length>  
        <Content-Type>text/html</Content-Type>  
        <Content-Encoding />  
        <Content-Language>en-US</Content-Language>  
        <Content-MD5 />  
        <Cache-Control>no-cache</Cache-Control>  
        <BlobType>BlockBlob</BlobType>  
        <LeaseStatus>unlocked</LeaseStatus>  
      </Properties>  
    </Blob>  
    <Blob>  
      <Name>blob2.txt</Name>  
      <Url>https://myaccount.blob.core.windows.net/mycontainer/blob2.txt</Url>  
      <Properties>  
        <Last-Modified>Sun, 27 Sep 2009 12:18:50 GMT</Last-Modified>  
        <Etag>0x8CAE7D55CF6C339</Etag>  
        <Content-Length>100</Content-Length>  
        <Content-Type>text/html</Content-Type>  
        <Content-Encoding />  
        <Content-Language>en-US</Content-Language>  
        <Content-MD5 />  
        <Cache-Control>no-cache</Cache-Control>  
        <BlobType>BlockBlob</BlobType>  
        <LeaseStatus>unlocked</LeaseStatus>  
      </Properties>  
    </Blob>  
    <BlobPrefix>  
      <Name>myfolder/</Name>  
    </BlobPrefix>  
    <Blob>  
      <Name>newblob1.txt</Name>  
      <Url>https://myaccount.blob.core.windows.net/mycontainer/newblob1.txt</Url>  
      <Properties>  
        <Last-Modified>Sun, 27 Sep 2009 16:31:57 GMT</Last-Modified>  
        <Etag>0x8CAE7D55CF6C339</Etag>  
        <Content-Length>25</Content-Length>  
        <Content-Type>text/html</Content-Type>  
        <Content-Encoding />  
        <Content-Language>en-US</Content-Language>  
        <Content-MD5 />  
        <Cache-Control>no-cache</Cache-Control>  
        <BlobType>BlockBlob</BlobType>  
        <LeaseStatus>unlocked</LeaseStatus>  
      </Properties>  
    </Blob>  
    <BlobPrefix>  
      <Name>myfolder2/</Name>  
    </BlobPrefix>  
  </Blobs>  
  <NextMarker>newblob2.txt</NextMarker>  
</EnumerationResults>  
"""


def remove_attributes(d: Dict[str, Any]) -> Dict[str, Any]:
    result = {}
    for k, v in d.items():
        if k.startswith("@"):
            continue
        if isinstance(v, dict):
            v = remove_attributes(v)
        result[k] = v
    return result


def test_parse():
    ref = xmltodict.parse(resp)
    ref = remove_attributes(ref)
    actual = xml.parse(resp.encode("utf8"), repeated_tags={"Blob", "BlobPrefix"})
    json_ref = json.dumps(ref, sort_keys=True, indent=" ")
    json_actual = json.dumps(actual, sort_keys=True, indent=" ")
    print(json_ref)
    print(json_actual)
    assert json_ref == json_actual


def test_unparse():
    body = {"BlockList": {"Latest": [str(i) for i in range(100)]}}
    ref = xmltodict.unparse(body).encode("utf8")
    actual = xml.unparse(body)
    print(ref)
    print(actual)
    assert ref == actual


def test_roundtrip():
    ref = xmltodict.parse(resp)
    ref = remove_attributes(ref)
    actual = xml.parse(xml.unparse(ref), repeated_tags={"Blob", "BlobPrefix"})

    json_ref = json.dumps(ref, sort_keys=True, indent=" ")
    json_actual = json.dumps(actual, sort_keys=True, indent=" ")
    print(json_ref)
    print(json_actual)

    assert actual == ref


def main():
    # benchmarking
    doc = xmltodict.parse(resp)
    doc = remove_attributes(doc)
    doc2 = doc.copy()
    doc2["EnumerationResults"]["Blobs"]["Blob"] = (
        doc2["EnumerationResults"]["Blobs"]["Blob"] * 300
    )
    expanded_resp = xmltodict.unparse(doc2)
    expanded_resp_utf8 = expanded_resp.encode("utf8")

    start = time.perf_counter()
    for _ in range(100):
        xmltodict.parse(expanded_resp)
    end = time.perf_counter()
    print(f"xmltodict parse elapsed {end - start}")

    start = time.perf_counter()
    for _ in range(100):
        lxml_parse(expanded_resp_utf8, repeated_tags={"Blob", "BlobPrefix"})
    end = time.perf_counter()
    print(f"lxml parse elapsed {end - start}")

    start = time.perf_counter()
    for _ in range(100):
        xmltodict.unparse(doc2)
    end = time.perf_counter()
    print(f"xmltodict unparse elapsed {end - start}")

    start = time.perf_counter()
    for _ in range(100):
        lxml_unparse(doc2)
    end = time.perf_counter()
    print(f"lxml unparse elapsed {end - start}")


if __name__ == "__main__":
    main()
