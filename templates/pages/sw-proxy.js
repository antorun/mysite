// Service Worker 代理 - 拦截请求并转发到穿山甲
// 运行在浏览器本地，绕开 CORS 限制（SW 内 fetch 不受 CORS 约束）

const TARGET_BASE = 'https://api-access.pangolin-sdk-toutiao.com';
const PROXY_PATH = '/__sw_proxy/';

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // 只拦截代理路径的请求
    if (!url.pathname.startsWith(PROXY_PATH)) return;
    
    // 提取真实目标路径
    const realPath = url.pathname.replace(PROXY_PATH, '/');
    const targetUrl = TARGET_BASE + realPath + url.search;
    
    // 构建转发请求
    const headers = new Headers(event.request.headers);
    // 修复 Host 头
    headers.set('Host', new URL(TARGET_BASE).host);
    
    const proxyRequest = new Request(targetUrl, {
        method: event.request.method,
        headers: headers,
        body: event.request.body,
        mode: 'cors',  // SW 中可用
    });
    
    event.respondWith(
        fetch(proxyRequest).then(response => {
            // 返回响应，添加 CORS 头让页面能读取
            const corsHeaders = new Headers(response.headers);
            corsHeaders.set('Access-Control-Allow-Origin', '*');
            corsHeaders.set('Access-Control-Expose-Headers', '*');
            
            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers: corsHeaders
            });
        }).catch(err => {
            return new Response(JSON.stringify({ error: 'SW Proxy Error: ' + err.message }), {
                status: 502,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        })
    );
});
