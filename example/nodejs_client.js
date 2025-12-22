/**
 * Fastls MITM代理 Node.js客户端示例
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

function testMitmProxy() {
    // MITM代理地址（需要先启动mitm_proxy.exe）
    const proxyUrl = 'http://127.0.0.1:8888';
    
    // 目标URL
    const targetUrl = 'https://tls.peet.ws/api/all';
    
    console.log('='.repeat(60));
    console.log('Fastls MITM代理 Node.js客户端示例');
    console.log('='.repeat(60));
    console.log();
    
    console.log('通过MITM代理访问目标URL...');
    console.log(`代理地址: ${proxyUrl}`);
    console.log(`目标URL: ${targetUrl}\n`);
    
    // 解析代理URL
    const proxy = new URL(proxyUrl);
    const target = new URL(targetUrl);
    
    // 配置代理选项
    const options = {
        hostname: proxy.hostname,
        port: proxy.port || 80,
        path: targetUrl,
        method: 'GET',
        headers: {
            'Host': target.hostname
        }
    };
    
    // 注意：Node.js的http模块不支持直接配置HTTP代理
    // 这里使用简单的代理转发方式
    // 实际使用中建议使用支持代理的库，如 axios 或 node-fetch
    
    const req = http.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log(`状态码: ${res.statusCode}`);
            console.log(`响应头:`, res.headers);
            console.log(`响应体长度: ${data.length} bytes`);
            
            // 显示响应内容（前500字符）
            /*if (data.length > 500) {
                console.log(`\n响应内容（前500字符）:\n${data.substring(0, 500)}`);
            } else {
                console.log(`\n响应内容:\n${data}`);
            }*/
            console.log(`\n响应内容:\n${data}`);
            
            console.log('\n' + '='.repeat(60));
            console.log('提示: 启动MITM代理时可以使用以下参数:');
            console.log('  -addr :8888          # 监听地址');
            console.log('  -browser chrome142   # 浏览器类型');
            console.log('  -ja3 <指纹>          # 自定义JA3指纹');
            console.log('  -ja4r <指纹>         # 自定义JA4R指纹');
            console.log('='.repeat(60));
        });
    });
    
    req.on('error', (error) => {
        console.error(`请求失败: ${error.message}`);
        console.log('\n请确保MITM代理已启动:');
        console.log('  cd services/fastls-mitm');
        console.log('  ./mitm_proxy.exe -addr :8888 -browser chrome142');
    });
    
    req.end();
}

// 使用axios的示例（需要安装: npm install axios）
function testWithAxios() {
    const axios = require('axios');
    const httpsAgent = require('https').Agent({
        rejectUnauthorized: false // 忽略SSL证书验证
    });
    
    const proxyUrl = 'http://127.0.0.1:8888';
    const targetUrl = 'https://tls.peet.ws/api/all';
    
    axios.get(targetUrl, {
        proxy: {
            host: '127.0.0.1',
            port: 8888
        },
        httpsAgent: httpsAgent,
        timeout: 30000
    })
    .then(response => {
        console.log(`状态码: ${response.status}`);
        console.log(`响应数据长度: ${JSON.stringify(response.data).length} bytes`);
    })
    .catch(error => {
        console.error(`请求失败: ${error.message}`);
    });
}

// 运行示例
if (require.main === module) {
    testMitmProxy();
    
    // 如果安装了axios，可以取消注释下面的行
    // testWithAxios();
}

module.exports = { testMitmProxy, testWithAxios };

