--处理响应报头和实际响应的不一致问题
local optionIsOn = function (options) return options == "on" and true or false end
local FilterID = optionIsOn(FilterID)
local FilterPhoneNumbers = optionIsOn(FilterPhoneNumbers)

----OpenResty提供了跟body_filter_by_lua*相对应的header_filter_by_lua*。header_filter会在Nginx发送报头之前调用，所以可以在这里置空Content-Length报头
if FilterID or FilterPhoneNumbers then
    ngx.header.content_length = nil
end

