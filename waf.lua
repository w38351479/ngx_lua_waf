local content_length=tonumber(ngx.req.get_headers()['content-length'])
local method=ngx.req.get_method()
local ngxmatch=ngx.re.match
if Abnormal_Proxy_Check() then
elseif Block_RequestMethod() then
elseif whiteip() then
elseif whitehost() then
elseif RefererLimit() then
elseif ContinuousAnomaliesCheck() then
elseif SlowDosCheck() then
elseif whiteua() then
elseif blockip() then
elseif whiteurl() then
elseif denycc() then
elseif ngx.var.http_Acunetix_Aspect then
    ngx.exit(444)
elseif ngx.var.http_X_Scan_Memo then
    ngx.exit(444)
elseif ua() then
elseif url() then
elseif args() then
elseif cookie() then
elseif country_white() then
elseif country_block() then
elseif PostCheck then
    if method=="POST" then  
        local boundary = get_boundary()
        if boundary then
            local len = string.len
            local sock, err = ngx.req.socket()
            if not sock then
                return
            end
            ngx.req.init_body(128 * 1024)
            sock:settimeout(0)
            local content_length = nil
            content_length=tonumber(ngx.req.get_headers()['content-length'])
            local content_type = nil
            content_type = ngx.req.get_headers()['content-type']
            local chunk_size = 4096
            if content_length < chunk_size then
                chunk_size = content_length
            end
            local size = 0
            while size < content_length do
                local data, err, partial = sock:receive(chunk_size)
                local data = data or partial
                if not data then
                    return
                end
                ngx.req.append_body(data)
                --文件内容检查
                if body(data) then
                    return true
                end
                size = size + len(data)
                --local m = ngxmatch(data,[[Content-Disposition: form-data;(.+)filename="(.+)\\.(.*)"]],'ijo')
                --单文件上传
                --local _,flname,lname = string.match(data,[[Content%-Disposition: form%-data;(.-)filename="([^\"]+)%.([^\"]-)".*]])
                --多文件上传i
                for  _,flname,lname in string.gmatch(data,[[Content%-Disposition: form%-data;(.-)filename="([^\"]+)%.([^\"]-)"]],'ijo') do
                    --文件后缀检查
                    if lname then
                        local fn = 'UploadFile: '..tostring(flname)..'.'..tostring(lname)
                        fileExtCheck(lname,fn,'content-type: '..content_type)
                        filetranslate = true
                    end
                end
                if ngxmatch(data,"Content%-Disposition:",'isjo') then
                    filetranslate = false
                end
                --文件内容检查
                if filetranslate==false then
                    if body(data) then
                        return true
                    end
                end
                local less = content_length - size
                if less < chunk_size then
                	chunk_size = less
                end
    	    end
    	    ngx.req.finish_body()
        else
            --post 参数检查
            ngx.req.read_body()
            local args = ngx.req.get_post_args(tonumber(max_post_vars) + 10)
            if not args then
                return
            end
            local tmp_post_nu = 0
            for key, val in pairs(args) do
                if type(val) == "table" then
                    tmp_post_nu = tmp_post_nu + #val
                    if type(val[1]) == "boolean" then
                        return
                    end
                    data=table.concat(val, ", ")
                else
                    data=val
                    tmp_post_nu = tmp_post_nu + 1
                end
                if data and type(data) ~= "boolean" and body(data) then
                    --内容检查
                    body(key)
                end
            end
            --post 参数数量检查，防止溢出攻击
            if tmp_post_nu > tonumber(max_post_vars) then
                log("-","Post too many parameters.")
                say_html("POST URL参数过多")
                ngx.exit(403)
            end
        end
    end
else
    return
end
