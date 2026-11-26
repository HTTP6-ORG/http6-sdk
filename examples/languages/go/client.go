package main
import("context";"encoding/json";"fmt";"io";"net";"net/http";"os";"regexp";"strings";"time")
func main(){
 if len(os.Args)!=4||!regexp.MustCompile(`^[a-z0-9-]{1,48}$`).MatchString(os.Args[2])||(os.Args[3]!="allowed"&&os.Args[3]!="denied"){panic("usage: client SOCKET OP allowed|denied")}
 amount:="100";if os.Args[3]=="denied"{amount="1100"}
 p:=map[string]any{"op":os.Args[2],"audience":"wallet","resource":"merchant-payment","args":map[string]any{"network":"regtest","recipient":"merchant-a","satoshis":amount},"holdSeconds":4}
 raw,e:=json.Marshal(p);if e!=nil{panic(e)}
 tr:=&http.Transport{DialContext:func(ctx context.Context,_,_ string)(net.Conn,error){return (&net.Dialer{}).DialContext(ctx,"unix",os.Args[1])}};defer tr.CloseIdleConnections()
 client:=http.Client{Transport:tr,Timeout:15*time.Second};r,e:=client.Post("http://agent.local/http6/v0/propose","application/json",strings.NewReader(string(raw)));if e!=nil{panic(e)};defer r.Body.Close();b,e:=io.ReadAll(io.LimitReader(r.Body,10*1024*1024));if e!=nil||!json.Valid(b){panic("invalid response")};fmt.Printf("{\"status\":%d,\"body\":%s}\n",r.StatusCode,b)
}
