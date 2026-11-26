using System.Net.Http;
using System.Net.Sockets;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Http6.Proposed;

public sealed record PilotResponse(int Status, JsonObject Body, byte[] RequestBytes);

// Experimental local fixture adapter. The caller independently supplies trust pins.
[System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
public sealed class PilotClient : IDisposable
{
    public const string Profile = "http6-wasix-delegation-02";
    readonly string agent, ledger, binary;
    static readonly HashSet<string> Meta = new() {"failureCore","failure","failureDecision","failureEventRef","failureEvidenceFile","proofStatus"};
    PilotClient(string agent, string ledger, string binary) { this.agent=agent; this.ledger=ledger; this.binary=binary; }
    public static PilotClient Attach(string stateDirectory, string pilotBinary)
    {
        var c=JsonNode.Parse(File.ReadAllText(Path.Combine(stateDirectory,"connections.json")))?.AsObject() ?? throw new InvalidDataException("Invalid connections");
        if ((string?)c["profile"]!=Profile) throw new InvalidDataException("Profile mismatch");
        return new PilotClient((string?)c["agent"] ?? throw new InvalidDataException("Missing agent"), (string?)c["ledger"] ?? throw new InvalidDataException("Missing ledger"), pilotBinary);
    }
    static void Pins(params string[] keys) { if (keys.Any(k=>!Regex.IsMatch(k ?? "", "^[0-9a-f]{64}$"))) throw new InvalidDataException("Valid independently configured trust pins required"); }
    static JsonObject Evidence(string path)
    {
        if (new FileInfo(path).Length>10*1024*1024) throw new InvalidDataException("Evidence limit");
        return JsonNode.Parse(File.ReadAllBytes(path))?.AsObject() ?? throw new InvalidDataException("Invalid evidence");
    }
    static void Compare(JsonObject body, JsonObject evidence, params string[] fields)
    {
        foreach(var field in fields) if (!body.ContainsKey(field) || !JsonNode.DeepEquals(body[field],evidence[field])) throw new InvalidDataException("Evidence mismatch: "+field);
    }
    static async Task<(int,JsonNode)> Request(string path, string method, string target, byte[]? body)
    {
        using var handler=new SocketsHttpHandler { ConnectCallback=async (_,ct)=> { var sock=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);try { await sock.ConnectAsync(new UnixDomainSocketEndPoint(path),ct);return new NetworkStream(sock,true); } catch { sock.Dispose();throw; } } };
        using var client=new HttpClient(handler) { Timeout=TimeSpan.FromSeconds(15) };
        using var request=new HttpRequestMessage(new HttpMethod(method),"http://agent.local"+target);
        if (body is not null) { request.Content=new ByteArrayContent(body);request.Content.Headers.ContentType=new System.Net.Http.Headers.MediaTypeHeaderValue("application/json"); }
        using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead);
        await using var input=await response.Content.ReadAsStreamAsync();using var buffer=new MemoryStream();var chunk=new byte[8192];int n;
        while((n=await input.ReadAsync(chunk))!=0){if(buffer.Length+n>10*1024*1024)throw new InvalidDataException("Response limit");buffer.Write(chunk,0,n);}
        return ((int)response.StatusCode,JsonNode.Parse(buffer.ToArray()) ?? throw new InvalidDataException("Invalid response"));
    }
    public async Task<PilotResponse> InvokeRawAsync(byte[] requestBytes)
    {
        if(requestBytes.Length>65536)throw new InvalidDataException("Request limit");var raw=(byte[])requestBytes.Clone();var (status,body)=await Request(agent,"POST","/http6/v0/propose",raw);return new(status,body.AsObject(),raw);
    }
    // Callers should use canonical pilot JSON bytes. The raw method preserves malformed bytes for evidence checks.
    public Task<PilotResponse> InvokeAsync(JsonObject proposal) => InvokeRawAsync(Canonical(proposal));
    static byte[] Canonical(JsonNode? value)
    {
        using var buffer=new MemoryStream();using(var w=new Utf8JsonWriter(buffer,new JsonWriterOptions { Encoder=System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))WriteCanonical(w,value);return buffer.ToArray();
    }
    static void WriteCanonical(Utf8JsonWriter w,JsonNode? n)
    {
        if(n is JsonObject o){w.WriteStartObject();foreach(var kv in o.OrderBy(k=>k.Key,StringComparer.Ordinal)){CheckAscii(kv.Key);w.WritePropertyName(kv.Key);WriteCanonical(w,kv.Value);}w.WriteEndObject();}
        else if(n is JsonArray a){w.WriteStartArray();foreach(var x in a)WriteCanonical(w,x);w.WriteEndArray();}
        else if(n is null)w.WriteNullValue();
        else {using var doc=JsonDocument.Parse(n.ToJsonString());var x=doc.RootElement;if(x.ValueKind==JsonValueKind.String){var s=x.GetString()!;CheckAscii(s);w.WriteStringValue(s);}else if(x.ValueKind==JsonValueKind.Number){if(!x.TryGetInt64(out var v)||v<0||v>9007199254740991L)throw new InvalidDataException("Unsupported number");w.WriteNumberValue(v);}else if(x.ValueKind==JsonValueKind.True||x.ValueKind==JsonValueKind.False)w.WriteBooleanValue(x.GetBoolean());else throw new InvalidDataException("Unsupported JSON value");}
    }
    static void CheckAscii(string s){if(s.Any(c=>c<32||c>126))throw new InvalidDataException("Unsupported pilot string");}
    public async Task<JsonArray> EventsAsync(){var (status,rows)=await Request(ledger,"GET","/http6/v0/events",null);if(status!=200||rows is not JsonArray list)throw new InvalidDataException("Ledger unavailable");return list;}
    async Task<string> Verify(string command, IEnumerable<string> args, JsonNode value)
    {
        var dir=Directory.CreateTempSubdirectory("http6-sdk-");try{
            var path=Path.Combine(dir.FullName,"evidence.json");var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite};
            await using(var f=new FileStream(path,options))await JsonSerializer.SerializeAsync(f,value);
            var psi=new ProcessStartInfo(binary){RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};psi.ArgumentList.Add(command);foreach(var arg in args)psi.ArgumentList.Add(arg);psi.ArgumentList.Add(path);
            using var p=Process.Start(psi) ?? throw new InvalidDataException("Verifier unavailable");using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var output=p.StandardOutput.ReadToEndAsync();var errors=p.StandardError.ReadToEndAsync();try {await p.WaitForExitAsync(timeout.Token);}catch(OperationCanceledException){p.Kill(true);await p.WaitForExitAsync();throw new TimeoutException("Verifier timed out");}
            await errors;if(p.ExitCode!=0)throw new InvalidDataException("Native verifier rejected evidence");return await output;
        }finally{dir.Delete(true);}
    }
    public async Task<JsonObject> VerifyResponseAsync(PilotResponse r,string evidenceFile,string operatorKey,string ledgerKey,string expectedOp)
    {
        Pins(operatorKey,ledgerKey);if(r.Status!=200||(string?)r.Body["response"]?["context"]?["op"]!=expectedOp)throw new InvalidDataException("Response status or operation mismatch");var e=Evidence(evidenceFile);Compare(r.Body,e,"result","receipt","response","responseDecision","responseEventRef");await Verify("verify-response",new[]{"--operator-key",operatorKey,"--ledger-key",ledgerKey},e);return new JsonObject{["verified"]=true,["scope"]="historical response evidence",["currentAuthorityVerified"]=false};
    }
    public async Task<JsonObject> VerifyFailureAsync(PilotResponse r,string evidenceFile,string operatorKey,string ledgerKey)
    {
        Pins(operatorKey,ledgerKey);var core=(JsonObject)r.Body.DeepClone();foreach(var k in Meta)core.Remove(k);if((string?)r.Body["proofStatus"]!="ledger-recorded"||!JsonNode.DeepEquals(core,r.Body["failureCore"]))throw new InvalidDataException("Failure response mismatch");var e=Evidence(evidenceFile);Compare(r.Body,e,"failureCore","failure","failureDecision","failureEventRef","error");var digest=Convert.ToHexString(SHA256.HashData(r.RequestBytes)).ToLowerInvariant();if((string?)e["requestHash"]!=digest||(int?)e["status"]!=r.Status)throw new InvalidDataException("Request or status mismatch");await Verify("verify-failure",new[]{"--operator-key",operatorKey,"--ledger-key",ledgerKey,"--request-hash",digest,"--status",r.Status.ToString(System.Globalization.CultureInfo.InvariantCulture)},e);return new JsonObject{["verified"]=true,["scope"]="historical gateway observation",["callerIdentityVerified"]=false,["effectStateVerified"]=false};
    }
    public async Task<JsonObject> VerifyLedgerAsync(JsonArray rows,string ledgerKey){Pins(ledgerKey);return JsonNode.Parse(await Verify("verify-ledger",new[]{"--ledger-key",ledgerKey},rows))!.AsObject();}
    public void Dispose() { }
}
