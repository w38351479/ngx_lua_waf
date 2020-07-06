local b64 = require 'ngx.base64'
local ngxmatch=ngx.re.match


--根据连续异常响应码分布，限制IP访问（拦截黑客针对不存在的URL地址发起的大量恶意访问）  
if ContinuousResponse then
   if ngx.status == 404 then
       --排除页面资源
       if not ngxmatch(ngx.var.uri,'\\.(png|jpg|ico|gif|jpeg|m3u8|css|js|flv|mp4|mp3|avc|mpg4|mov|mid|wav|ts|aiff|au|swf|ogg|webm|pdf|csv|log|txt|xlsx|doc|yaml|yml|drawio|json|docx|xmind)$',"ijo") then
           local uri = b64.encode_base64url(tostring(ngx.var.uri))
           local now_ip = getClientIp()
           local token = now_ip .. '#' ..uri
           local respstatus = ngx.shared.respstatus
           local req, _ = respstatus:get(token)
           if not req then
               respstatus:set(token, 1,300)
           end

       end
   end
end


--http慢速攻击
if SlowDos then
    if ngx.status == 408 then
        local now_ip = getClientIp()
        local respstatus = ngx.shared.respstatus
        local req, _ = respstatus:get(now_ip)
        local slowCCseconds = tonumber(string.match(SlowDosCrate, "/(.*)"))
        if req then
            respstatus:incr(now_ip, 1)
        else
            respstatus:set(now_ip, 1,slowCCseconds)
        end
    end
end
