# 项目名称
mini rust desk的公共函数.


- **mini_rust_desk_id_server**  
ID注册服务器: 负责为客户端(mini_rust_desk_client mini_rust_desk_server)提供 peer 端的地址和公钥 pk、RelayServer的地址
- **mini_rust_desk_relay_server**  
中继服务器: 负责在多个客户端之间转发 video、audio 流
- **mini_rust_desk_client**  
用于连接/控制的Client端
- **mini_rust_desk_server**  
被连接/控制的Server端
