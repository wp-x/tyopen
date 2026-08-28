#!/bin/bash

# TyOpen 一键启动脚本
# 同时启动后端和前端开发服务器
# 按 Ctrl+C 自动结束所有服务

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志文件
BACKEND_LOG=""
FRONTEND_LOG=""

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
BACKEND_LOG="$SCRIPT_DIR/backend.log"
FRONTEND_LOG="$SCRIPT_DIR/web/frontend.log"

# 加载本地开发配置（包含管理员密码和 JWT 密钥）
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
fi

# 存储子进程 PID
BACKEND_PID=""
FRONTEND_PID=""

# 时间戳
timestamp() {
    date +"%H:%M:%S"
}

print_ok() {
    echo -e "${GREEN}[$(timestamp)] $1${NC}"
}

print_warn() {
    echo -e "${YELLOW}[$(timestamp)] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[$(timestamp)] $1${NC}"
}

print_err() {
    echo -e "${RED}[$(timestamp)] $1${NC}"
}

port_in_use() {
    local port="$1"
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
}

show_port_owner() {
    local port="$1"
    lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print "  - " $1 " (PID " $2 ") " $9}'
}

# 清理函数
cleanup() {
    echo ""
    echo -e "${YELLOW}正在停止服务...${NC}"
    
    # 停止后端
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo -e "${BLUE}停止后端 (PID: $BACKEND_PID)${NC}"
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    
    # 停止前端
    if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        echo -e "${BLUE}停止前端 (PID: $FRONTEND_PID)${NC}"
        kill "$FRONTEND_PID" 2>/dev/null || true
        wait "$FRONTEND_PID" 2>/dev/null || true
    fi
    
    # 额外清理可能残留的进程
    pkill -f "tyopen" 2>/dev/null || true
    pkill -f "vite.*电信网盘" 2>/dev/null || true
    
    echo -e "${GREEN}✓ 所有服务已停止${NC}"
    exit 0
}

# 捕获退出信号
trap cleanup SIGINT SIGTERM EXIT

# 打印 Banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║           TyOpen 开发服务器               ║"
echo "║      电信天翼云盘直链分享工具             ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# 编译后端（每次启动都重新编译，确保代码变更生效）
print_info "正在编译后端..."
go build -o tyopen ./cmd/server
print_ok "后端编译完成"

# 检查前端依赖
if [ ! -d "./web/node_modules" ]; then
    print_warn "前端依赖未安装，正在安装..."
    cd web && npm install && cd ..
    print_ok "前端依赖安装完成"
fi

echo ""
print_info "端口检查..."
if port_in_use 10000; then
    print_err "后端端口 10000 已被占用，请先停止占用进程"
    show_port_owner 10000
    exit 1
else
    print_ok "后端端口 10000 可用"
fi
if port_in_use 3000; then
    print_err "前端端口 3000 已被占用，请先停止占用进程"
    show_port_owner 3000
    exit 1
else
    print_ok "前端端口 3000 可用"
fi

echo ""
print_info "启动服务..."
echo ""

# 启动后端
print_info "▶ 启动后端 (端口 10000)"
: > "$BACKEND_LOG"
./tyopen > "$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
sleep 1

# 检查后端是否成功启动
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    print_err "后端启动失败，请查看日志：$BACKEND_LOG"
    exit 1
fi
print_ok "后端已启动 (PID: $BACKEND_PID)"

# 启动前端
print_info "▶ 启动前端 (端口 3000)"
: > "$FRONTEND_LOG"
cd web && npm run dev > "$FRONTEND_LOG" 2>&1 &
FRONTEND_PID=$!
cd ..
sleep 2

# 检查前端是否成功启动
if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    print_err "前端启动失败，请查看日志：$FRONTEND_LOG"
    cleanup
    exit 1
fi
print_ok "前端已启动 (PID: $FRONTEND_PID)"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ 所有服务已启动！${NC}"
echo ""
echo -e "  ${BLUE}前端地址:${NC} http://localhost:3000"
echo -e "  ${BLUE}后端地址:${NC} http://localhost:10000"
echo -e "  ${BLUE}管理员密码:${NC} 已从 .env 加载"
echo ""
echo -e "  ${BLUE}后端日志:${NC} $BACKEND_LOG"
echo -e "  ${BLUE}前端日志:${NC} $FRONTEND_LOG"
echo ""
if port_in_use 10000; then
    echo -e "  ${GREEN}后端端口:${NC} 10000 已监听"
else
    echo -e "  ${RED}后端端口:${NC} 10000 未监听（请查看日志）"
fi
if port_in_use 3000; then
    echo -e "  ${GREEN}前端端口:${NC} 3000 已监听"
else
    echo -e "  ${RED}前端端口:${NC} 3000 未监听（请查看日志）"
fi
echo ""
echo -e "${YELLOW}  按 Ctrl+C 停止所有服务${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""

# 等待子进程
wait
