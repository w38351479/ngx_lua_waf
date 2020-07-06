require "lfs"
echarts_html=[[
<!DOCTYPE html>
<html style="height: 100%%">
   <head>
       <meta charset="utf-8">
   </head>
   <body style="height: 100%%; margin: 0;text-align:center">

    <br>
    <div class="mycontainer">选择日期：
    <input type="text" placeholder="示例：2020-06-30" id="date">
    <input type="button" value="转到" onclick="getData()" />
    <input type="button" value="今天" onclick="nowday()" />
    <script type="text/javascript">
    function getData() {
        //获取输入框的文本
        var date_v=document.getElementById('date').value;
        var all_url = document.location.toString();
        var arrUrl = all_url.split("?");
        var url = arrUrl[0];
        window.location.href=url + '?dt=' +date_v;
    };
    function nowday() {
        window.location.href='/waf_analysis';
    }
    </script>
    </div><br><br>


       <div id="container" style="height: 100%%"></div>
       <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/echarts/dist/echarts.min.js"></script>
       <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/echarts-gl/dist/echarts-gl.min.js"></script>
       <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/echarts-stat/dist/ecStat.min.js"></script>
       <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/echarts/dist/extension/dataTool.min.js"></script>
       <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/echarts/map/js/china.js"></script>
       <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/echarts/map/js/world.js"></script>
       <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/echarts/dist/extension/bmap.min.js"></script>


       <script type="text/javascript">
var dom = document.getElementById("container");
var myChart = echarts.init(dom);
var app = {};
option = null;

//var data = {seriesData:[{name: "SQL注入", value: 94079},{name: "非法User-Agent", value: 10360},{name: "非法文件上传", value: 96591}]}
var data = %s;

option = {
    title: {
        text: '%s WAF受攻击情况统计',
        subtext: '一天内受攻击情况',
        left: 'center'
    },
    tooltip: {
        trigger: 'item',
        formatter: '{a} <br/>{b} : {c} ({d}%%)'
    },
    legend: {
        type: 'scroll',
        orient: 'vertical',
        right: 10,
        top: 20,
        bottom: 20,
        data: data.legendData,

        selected: data.selected
    },
    series: [
        {
            name: '攻击类型',
            type: 'pie',
            radius: '65%%',
            center: ['45%%', '50%%'],
            data: data.seriesData,
            emphasis: {
                itemStyle: {
                    shadowBlur: 10,
                    shadowOffsetX: 0,
                    shadowColor: 'rgba(0, 0, 0, 0.5)'
                }
            }
        }
    ],
    color: ['#00CD00','#8470FF','#c23531','#2f4554', '#61a0a8', '#d48265', '#91c7ae','#749f83','#ca8622', '#bda29a','#6e7074', 
'#546570', '#c4ccd3','#006400','#8B4789','#00B2EE','#8968CD','#C71585','#B3EE3A','#4876FF','#B0E2FF','#FFC125','#EE82EE']

};


if (option && typeof option === "object") {
    myChart.setOption(option, true);
}
       </script>
   </body>
</html>
]]



function FindLogFile(fileday)
    local path = "/usr/local/openresty/nginx/waflogs"
    local str_date = string.gsub(fileday,'%-','%%-')
    local file_list = {}
    for file in lfs.dir(path) do
        if file ~= "." and file ~= ".." then
            if string.match(file,str_date.."_sec%.log$") or string.match(file,str_date.."_UploadFileFailed%.log$") then
                local f = path..'/'..file
                table.insert(file_list,f)
            end
        end
    end
    return file_list
end

function LogCount(nowday)
    local fl = FindLogFile(nowday)
    --nginx server_name白名单主机
    local while_host_v = 0
    --args攻击
    local args_attack = 0
    --URL攻击
    local url_attack = 0
    --非法User-Agent
    local ua_attack = 0
    --cookie攻击
    local cookie_attack = 0
    --URL访问太频繁
    local url_more = 0
    --IP访问太频繁
    local ip_more = 0
    --伪造爬虫
    local forge_ua = 0
    --合法文件后缀上传
    local allow_suffixes = 0
    --非法文件后缀上传
    local not_support_suffixes = 0
    --禁止特定Referer访问
    local blockReferer = 0
    --请求方法不允许
    local bad_request_method = 0
    --连续响应异常状态码
    local continuous_request = 0
    --慢速攻击
    local slow_attack = 0
    --使用非法代理访问
    local abnormal_proxy_attack = 0

    if fl ~= nil then    
        for k,v in pairs(fl) do
            local log_file=io.lines(v)
            for gongji_value in log_file do
                if string.match(gongji_value,"white host") then
                    while_host_v = while_host_v + 1
                elseif string.match(gongji_value,"args in attack rules")  then
                    args_attack = args_attack + 1
                elseif string.match(gongji_value,"url in attack rules")  then
                    url_attack = url_attack + 1
                elseif string.match(gongji_value,"ua in attack rules")  then
                    ua_attack = ua_attack + 1
                elseif string.match(gongji_value,"cookie in attack rules")  then
                    cookie_attack = cookie_attack + 1
                elseif string.match(gongji_value,"IP get url over")  then
                    url_more = url_more + 1
                elseif string.match(gongji_value,"IP get host over")  then
                    ip_more = ip_more + 1
                elseif string.match(gongji_value,"Suspected forged reptile")  then
                    forge_ua = forge_ua + 1
                elseif string.match(gongji_value,"Allowed file suffixes")  then
                    allow_suffixes = allow_suffixes + 1
                elseif string.match(gongji_value,"File suffix is not supported")  then
                    not_support_suffixes = not_support_suffixes + 1
                elseif string.match(gongji_value,"BlockReferer in attack rules")  then
                    blockReferer = blockReferer + 1
                elseif string.match(gongji_value,"Request method not allowed")  then
                    bad_request_method = bad_request_method + 1
                elseif string.match(gongji_value,"Continuous request exception")  then
                    continuous_request = continuous_request + 1
                elseif string.match(gongji_value,"Suspected slow attack") then
                    slow_attack = slow_attack + 1
                elseif string.match(gongji_value,"Abnormal proxy attack") then
                    abnormal_proxy_attack = abnormal_proxy_attack + 1
                end
            end
        end
    end
    local data = '{seriesData:[{name: "nginx的server_name白名单(%s)", value: %s},{name: "args攻击(%s)", value: %s},{name: "URL攻击(%s)", value: %s},{name: "非法User-Agent(%s)", value: %s},{name: "cookie攻击(%s)", value: %s},{name: "URL访问太频繁(%s)", value: %s},{name: "IP访问太频繁(%s)", value: %s},{name: "伪造爬虫(%s)", value: %s},{name: "合法文件后缀上传(%s)", value: %s},{name: "非法文件后缀上传(%s)", value: %s},{name: "禁止特定Referer访问(%s)", value: %s},{name: "请求方法不允许(%s)", value: %s},{name: "连续响应异常状态码(%s)", value: %s},{name: "疑似慢速攻击(%s)", value: %s},{name: "使用非法代理访问(%s)", value: %s}]}'

    local format_data = string.format(data,tostring(while_host_v),tostring(while_host_v),
                          tostring(args_attack),tostring(args_attack), 
                          tostring(url_attack),tostring(url_attack),
                          tostring(ua_attack),tostring(ua_attack),
                          tostring(cookie_attack),tostring(cookie_attack),
                          tostring(url_more),tostring(url_more),
                          tostring(ip_more),tostring(ip_more),
                          tostring(forge_ua),tostring(forge_ua),
                          tostring(allow_suffixes),tostring(allow_suffixes),
                          tostring(not_support_suffixes),tostring(not_support_suffixes),
                          tostring(blockReferer),tostring(blockReferer),
                          tostring(bad_request_method),tostring(bad_request_method),
                          tostring(continuous_request),tostring(continuous_request),
                          tostring(slow_attack),tostring(slow_attack),
                          tostring(abnormal_proxy_attack),tostring(abnormal_proxy_attack)
                          )
    return format_data
end 


local args = ngx.req.get_uri_args()
local riqi = os.date("%Y-%m-%d")
if args then
    for key, val in pairs(args) do
        if key == "dt" and string.match(val,"%d+%-%d+%-%d+") then
            riqi = val
        end
    end
end
ngx.status = ngx.HTTP_OK
ngx.say(string.format(echarts_html,LogCount(riqi),riqi))
ngx.exit(ngx.status) 
