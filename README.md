# 原型污染检测器

针对内部对象工具库(merge / deepMerge / deepClone / setPath / defaultsDeep …)的自动化原型污染检测。

## 结构

```
lib/object-utils.vulnerable.js   有漏洞的工具库(演示/验证用,勿上生产)
lib/object-utils.safe.js         修复后的安全版本(功能等价,见文件头修复要点)
detector/detect.js               Node 检测器(vm 隔离 + 自动函数发现 + 载荷最小化)
report/index.html                Lit 结果页(读取同目录 results.js)
report/results.js                检测器生成的结果数据
```

## 使用

```bash
node detector/detect.js \
  vulnerable=lib/object-utils.vulnerable.js \
  safe=lib/object-utils.safe.js

open report/index.html   # 结果页通过 CDN 加载 Lit,需联网
```

退出码:任一被测库存在**全局原型污染**发现时为 `1`,可直接接入 CI。

## 检测原理

1. **自动发现**:在 `vm` 沙箱中加载被测库,枚举全部导出函数;按参数名
   (`path|key|prop|…`)区分"路径类"与"对象类"攻击策略。
2. **隔离执行**:每个用例都在全新的 `vm` realm 中运行 —— 该 realm 有独立的
   `Object.prototype`,污染不会外溢到宿主进程,用例之间也不串扰。
3. **两类判定**:
   - 全局原型污染:realm 内 `Object.prototype` / `Function.prototype` 出现标记键;
   - 返回对象原型注入:返回值的原型被替换成带标记键的对象。
4. **最小复现**:对命中的对象载荷做贪心收缩(删键 / 取子树),路径载荷按长度
   升序首个命中即最小;报告中给出可直接执行的复现表达式。
5. **修复建议**:按污染向量(`__proto__` / `constructor.prototype` / 路径注入 /
   返回对象原型注入)生成对应建议。

## 当前检测结果

| 函数 | 漏洞版 | 安全版 |
|---|---|---|
| `merge` | 返回对象原型注入(`__proto__`) | 干净 |
| `deepMerge` | 全局污染(`__proto__`、`constructor.prototype`) | 干净 |
| `deepClone` | 返回对象原型注入(`__proto__`) | 干净 |
| `setPath` | 全局污染(4 种路径) | 干净(非法段抛 TypeError) |
| `defaultsDeep` | 全局污染(两种向量) | 干净 |
| `getPath` / `isObject` / `isPlainObject` | 干净 | 干净 |

## 扩展

- 新增攻击载荷:编辑 `detect.js` 顶部的 `OBJECT_PAYLOADS` / `PATH_PAYLOADS`。
- 检测自己的库:`node detector/detect.js mylib=path/to/your-lib.js`。
