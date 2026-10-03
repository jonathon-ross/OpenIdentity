package org.openidentity.spring.auth;
import org.springframework.http.MediaType;import org.springframework.web.bind.annotation.*;import java.net.URLEncoder;import java.nio.charset.StandardCharsets;
@RestController
@RequestMapping("/openidentity/auth/login")
public final class OpenIdentityNativeLoginPageController {
 @GetMapping(produces=MediaType.TEXT_HTML_VALUE)
 public String login(@RequestParam("continue") String target){
  if(target==null||!target.startsWith("/oauth2/authorize?")||target.startsWith("//")||target.indexOf(13)>=0||target.indexOf(10)>=0)throw new IllegalArgumentException("continue");
  String escaped=target.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");
  return "<!doctype html><html><head><meta charset='utf-8'><title>OpenIdentity Native Authentication</title></head><body><h1>OpenIdentity Native Authentication</h1><p>Authenticate this authorization request with an external OI-015 authenticator.</p><pre id='target'>"+escaped+"</pre><button id='challenge'>Create challenge</button><pre id='challengeOut'></pre><textarea id='assertion' rows='8' cols='100' placeholder='Paste assertionBase64Url from the external authenticator'></textarea><br><button id='verify'>Verify and continue</button><pre id='status'></pre><script>let cid=null;const target=document.getElementById('target').textContent;document.getElementById('challenge').onclick=async()=>{const r=await fetch('/openidentity/auth/login/challenge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestTarget:target})});const j=await r.json();cid=j.challengeId;document.getElementById('challengeOut').textContent=JSON.stringify(j,null,2)};document.getElementById('verify').onclick=async()=>{const r=await fetch('/openidentity/auth/login/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challengeId:cid,assertionBase64Url:document.getElementById('assertion').value.trim()})});const j=await r.json();if(r.ok){location.href=j.continue}else{document.getElementById('status').textContent='Authentication rejected'}};</script></body></html>";
 }
}