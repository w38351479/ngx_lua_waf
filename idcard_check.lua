--验证身份证信息
--只支持18位身份证的验证

--[[
#身份证18位编码规则：dddddd yyyymmdd xxx y   
#dddddd：地区码   
#yyyymmdd: 出生年月日   
#xxx:顺序类编码，无法确定，奇数为男，偶数为女   
#y: 校验码，该位数值可通过前17位计算获得  
#<p />  
#18位号码加权因子为(从右到左) Wi = [ 7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2,1 ]  
#验证位 Y = [ 1, 0, 10, 9, 8, 7, 6, 5, 4, 3, 2 ]   
#校验位计算公式：Y_P = mod( ∑(Ai×Wi),11 )   
#i为身份证号码从右往左数的 2...18 位; Y_P为脚丫校验码所在校验码数组位置  
参考代码:
      https://github.com/yujinqiu/idlint
]]
local string_len = string.len
local tonumber = tonumber

-- // wi =2(n-1)(mod 11) 
local wi = { 7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2, 1 }; 
-- // verify digit 
local vi= { '1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2' }; 

local function isBirthDate(date)
    local year = tonumber(date:sub(1,4))
    local month = tonumber(date:sub(5,6))
    local day = tonumber(date:sub(7,8))
    if year < 1900 or year > 2100 or month >12 or month < 1 then
        return false
    end
    -- //月份天数表
    local month_days = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    local bLeapYear = (year % 4 == 0 and year % 100 ~= 0) or (year % 400 == 0)
    if bLeapYear  then
        month_days[2] = 29;
    end

    if day > month_days[month] or day < 1 then
        return false
    end

    return true
end

local function isAllNumberOrWithXInEnd( str )
    local ret = str:match("%d+X?") 
    return ret == str 
end


local function checkSum(idcard)
    -- copy from http://stackoverflow.com/questions/829063/how-to-iterate-individual-characters-in-lua-string
    local nums = {}
    local _idcard = idcard:sub(1,17)
    for ch in _idcard:gmatch"." do
        table.insert(nums,tonumber(ch))
    end
    local sum = 0
    for i,k in ipairs(nums) do
        sum = sum + k * wi[i]
    end

    return vi [sum % 11+1] == idcard:sub(18,18 )
end



function verifyIDCard(idcard)
    if string_len(idcard) ~= 18 then
        return false
    end

    if not isAllNumberOrWithXInEnd(idcard) then
        return false
    end
    -- //第1-2位为省级行政区划代码，[11, 65] (第一位华北区1，东北区2，华东区3，中南区4，西南区5，西北区6)
    local nProvince = tonumber(idcard:sub(1, 2))
    if( nProvince < 11 or nProvince > 65 ) then
        return false
    end

    -- //第3-4为为地级行政区划代码，第5-6位为县级行政区划代码因为经常有调整，这块就不做校验

    -- //第7-10位为出生年份；//第11-12位为出生月份 //第13-14为出生日期
    if not isBirthDate(idcard:sub(7,14)) then
        return false
    end

    if not checkSum(idcard) then
        return false
    end

    return true
end

