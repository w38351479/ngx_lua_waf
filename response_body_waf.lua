--处理返回的数据请求

require 'config'
require 'idcard_check'
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir
local unescape=ngx.unescape_uri
local FilterID = optionIsOn(FilterID)
local FilterPhoneNumbers = optionIsOn(FilterPhoneNumbers)
local Desensitization_log = optionIsOn(Desensitization_log)


-- 获取流当前响应数据
local chunk, eof = ngx.arg[1], ngx.arg[2]
-- 定义全局变量，收集全部响应
if ngx.ctx.buffered == nil then
    ngx.ctx.buffered = {}
end

-- 如果非最后一次响应，将当前响应赋值
if chunk ~= "" and not ngx.is_subrequest then
    table.insert(ngx.ctx.buffered, chunk)

    -- 将当前响应赋值为空，以修改后的内容作为最终响应
    ngx.arg[1] = nil
end

local WhiteFileFilter_tmp = true
-- 如果为最后一次响应，对所有响应数据进行处理
if eof then
    -- 获取所有响应数据
    local whole = table.concat(ngx.ctx.buffered)
    ngx.ctx.buffered = nil

    for _,rule in pairs(WhiteFileFilter_rules) do
        if rule =="" or ngx.re.match(unescape(ngx.var.request_uri),rule,"isjo")  then
            WhiteFileFilter_tmp = false
            --DesensitizationLog("skip url: ".. rule)
            break
        end
    end

    -- 进行你所需要进行的处理
    -- 身份证号码脱敏
    if FilterID and WhiteFileFilter_tmp then
        --lua 默认不支持POSIX规范，所以这里身份证替换不是特别精准
        --身份证号码为15位或者18位，15位不在考虑范围内，18位前17位为数字，最后一位是校验位，可能为数字或字符X
        -- [1-9]\d{5}(18|19|([23]\d))\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx] 
        --找到符合前后无数字的大致字符串
        whole,l_n,l_err = ngx.re.gsub(whole,'([^\\d][1-9]\\d{4})(\\d(18|19|([23]\\d))\\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\\d)(\\d{2}[0-9Xx][^\\d])',"$1".."**********".."$10")
        if Desensitization_log then
            for p_string in  string.gmatch(whole,'[1-9]%d%d%d%d%*%*%*%*%*%*%*%*%*%*%d%d[0-9Xx]') do
                DesensitizationLog("Desensitization idcard: ".. p_string)
            end
        end

        --whole, n, err = string.gsub(whole,"[^%d]([1-9][0-9][0-9][0-9][0-9][0-9])([0-9][0-9][0-9][0-9][0-9][0-9][0-9])([0-9][0-9])[^%d]","%1".."**********".."%3")
    end
    -- 手机号码脱敏
    if whole ~= nil then
        if FilterPhoneNumbers and WhiteFileFilter_tmp then
            --whole, y_n, y_err = ngx.re.gsub(whole,"([^\\d](13[0-9])|(14[579])|(15([0-3]|[5-9]))|(16[6])|(17[0135678])|(18[0-9])|(19[89]))(\\d{4})(\\d{4}[^\\d])","$1".."****".."$11")
            whole, y_n, y_err = ngx.re.gsub(whole,"(((([^\\d]|^)(13[0-9]))|(([^\\d]|^)(14[579]))|(([^\\d]|^)(15([0-3]|[5-9])))|(([^\\d]|^)(16[6]))|(([^\\d]|^)(17[0135678]))|(([^\\d]|^)(18[0-9]))|(([^\\d]|^)(19[89])))(\\d{4})((\\d{4})(?!\\d+)))","$2".."****".."$26")
            if Desensitization_log then
                for p_string in  string.gmatch(whole,'1%d%d%*%*%*%*%d%d%d%d') do
                    DesensitizationLog("Desensitization phone number: ".. p_string)
                end
            end
        end
    end

    -- 重新赋值响应数据，以修改后的内容作为最终响应
    ngx.arg[1] = whole
end



--记录上传的文件
function DesensitizationLog(tm_info)
    if Desensitization_log then
        local realIp = ngx.var.remote_addr
        local headers = ngx.resp.get_headers()
        local content_type = headers['content-type'] or '-'
        local time=ngx.localtime()
        local servername=ngx.var.host 
        local ua = ngx.var.http_user_agent
        local url = ngx.var.request_uri
        local filename = logpath..'/'..servername.."_"..ngx.today().."_DesensitizationData.log"
        if ua  then
            local line = realIp.." ["..time.."] \""..servername..url.."\" \""..content_type.. "\" \""..ua.."\" \""..tm_info.."\"\n"
            write(filename,line)
        else
            local line = realIp.." ["..time.."] \""..servername..url.."\" \""..content_type.. "\" \"".."-".."\" \""..tm_info.."\"\n"
            write(filename,line)
        end
    end
end
