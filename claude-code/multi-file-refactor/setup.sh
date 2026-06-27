#!/usr/bin/env bash
# setup.sh — 一键搭好「多文件协同与终端代码级重构」实验工作区
#
# 用途：把 financial-automation + CRM-Assistant 快照进本目录，建好各自的 venv，
#       跑通「重构前」绿色基线。
#
# 运行：在仓库根执行 bash claude-code/multi-file-refactor/setup.sh

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DST="claude-code/multi-file-refactor"
MIRROR="https://pypi.tuna.tsinghua.edu.cn/simple"

# 检查是否已存在
if [ -e "$DST/financial-automation" ] || [ -e "$DST/CRM-Assistant" ]; then
    echo "⚠ $DST 下已有快照，为避免覆盖已有改动，脚本退出。"
    echo "  如需从头重建：rm -rf $DST/financial-automation $DST/CRM-Assistant $DST/common  然后重跑。"
    exit 1
fi

echo "==> 1/5 快照 financial-automation + CRM-Assistant 到 $DST/"
mkdir -p "$DST/common"

# 正确复制两个子目录（注意末尾没有/，这样复制的是目录本身）
for app in financial-automation CRM-Assistant; do
    echo "  复制 $app..."
    rsync -a --exclude '.venv' --exclude 'runtime' --exclude '__pycache__' \
            --exclude '*.pyc' --exclude '.tmp_tests' \
            "$app/" "$DST/$app/"
done

echo "==> 2/5 financial-automation：建 venv + 装依赖（国内镜像）"
( cd "$DST/financial-automation"
  python3 -m venv .venv
  ./.venv/bin/pip install -q -i "$MIRROR" -r requirements.txt )

echo "==> 3/5 CRM-Assistant：建 venv（标准库，无三方依赖）"
( cd "$DST/CRM-Assistant" && python3 -m venv .venv )

echo "==> 4/5 注入 common/feishu 到两个 venv（.pth，业务代码里零 sys.path）"
WORKSPACE_ROOT="$(git rev-parse --show-toplevel)/$DST"
for app in financial-automation CRM-Assistant; do
  SITE="$("$DST/$app/.venv/bin/python" -c 'import site;print(site.getsitepackages()[0])')"
  echo "$WORKSPACE_ROOT" > "$SITE/feishu_common.pth"
done

echo "==> 5/5 跑「重构前」绿色基线"
echo "-- 测试 financial-automation --"
( cd "$DST/financial-automation" && ./.venv/bin/python -m unittest tests.test_smoke )
echo ""
echo "-- 测试 CRM-Assistant --"
( cd "$DST/CRM-Assistant"
  ./.venv/bin/python scripts/crm_assistant.py run-merge-policy-tests )

echo ""
echo "✅ 工作区就绪：$DST"
echo "   - financial-automation 测试通过"
echo "   - CRM-Assistant 测试通过"
echo "   可以开始第 17 节重构了！"
