window.__PP_RESULTS__ = {
  "tool": "prototype-pollution-detector",
  "generatedAt": "2026-11-17T16:48:19.140Z",
  "node": "v26.8.1",
  "marker": "ppMarker7f3a",
  "libs": [
    {
      "label": "vulnerable",
      "file": "lib/object-utils.vulnerable.js",
      "functions": [
        {
          "name": "merge",
          "params": [
            "target",
            "sources"
          ],
          "arity": 1,
          "tested": 24,
          "findings": [
            {
              "strategy": "object",
              "vector": "__proto__",
              "pollutionType": "returned-object-proto",
              "severity": "medium",
              "payload": "{\"__proto__\":{\"ppMarker7f3a\":1}}",
              "repro": "merge({}, JSON.parse('{\"__proto__\":{\"ppMarker7f3a\":1}}'))",
              "fixes": [
                "遍历来源对象时改用 Object.keys 只取自有键,并显式跳过 __proto__;或对赋值改用 Object.defineProperty,避免触发原型 setter。",
                "创建承接拷贝的对象时使用 Object.create(null),或为 __proto__ 键使用 Object.defineProperty 定义普通数据属性,避免调用方拿到原型被篡改的对象。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            }
          ]
        },
        {
          "name": "deepMerge",
          "params": [
            "target",
            "source"
          ],
          "arity": 2,
          "tested": 24,
          "findings": [
            {
              "strategy": "object",
              "vector": "__proto__",
              "pollutionType": "global-prototype",
              "severity": "high",
              "payload": "{\"__proto__\":{\"ppMarker7f3a\":1}}",
              "repro": "deepMerge({}, JSON.parse('{\"__proto__\":{\"ppMarker7f3a\":1}}'))",
              "fixes": [
                "遍历来源对象时改用 Object.keys 只取自有键,并显式跳过 __proto__;或对赋值改用 Object.defineProperty,避免触发原型 setter。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            },
            {
              "strategy": "object",
              "vector": "constructor.prototype",
              "pollutionType": "global-prototype",
              "severity": "high",
              "payload": "{\"constructor\":{\"prototype\":{\"ppMarker7f3a\":1}}}",
              "repro": "deepMerge({}, JSON.parse('{\"constructor\":{\"prototype\":{\"ppMarker7f3a\":1}}}'))",
              "fixes": [
                "把 constructor / prototype 列入键名黑名单;递归合并前确认目标是普通对象(Object.getPrototypeOf 为 Object.prototype 或 null),不要递归进函数。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            }
          ]
        },
        {
          "name": "deepClone",
          "params": [
            "obj"
          ],
          "arity": 1,
          "tested": 24,
          "findings": [
            {
              "strategy": "object",
              "vector": "__proto__",
              "pollutionType": "returned-object-proto",
              "severity": "medium",
              "payload": "{\"__proto__\":{\"ppMarker7f3a\":1}}",
              "repro": "deepClone(JSON.parse('{\"__proto__\":{\"ppMarker7f3a\":1}}'))",
              "fixes": [
                "遍历来源对象时改用 Object.keys 只取自有键,并显式跳过 __proto__;或对赋值改用 Object.defineProperty,避免触发原型 setter。",
                "创建承接拷贝的对象时使用 Object.create(null),或为 __proto__ 键使用 Object.defineProperty 定义普通数据属性,避免调用方拿到原型被篡改的对象。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            }
          ]
        },
        {
          "name": "setPath",
          "params": [
            "obj",
            "path",
            "value"
          ],
          "arity": 3,
          "tested": 32,
          "findings": [
            {
              "strategy": "path",
              "vector": "__proto__",
              "pollutionType": "global-prototype",
              "severity": "high",
              "payload": "__proto__.ppMarker7f3a",
              "repro": "setPath({}, \"__proto__.ppMarker7f3a\", 'polluted')",
              "fixes": [
                "遍历来源对象时改用 Object.keys 只取自有键,并显式跳过 __proto__;或对赋值改用 Object.defineProperty,避免触发原型 setter。",
                "对路径解析出的每一段做黑名单校验(__proto__、constructor、prototype 直接抛 TypeError),可参考 lodash >= 4.17.12 中 _.set 的修复方式。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            },
            {
              "strategy": "path",
              "vector": "constructor.prototype",
              "pollutionType": "global-prototype",
              "severity": "high",
              "payload": "constructor.prototype.ppMarker7f3a",
              "repro": "setPath({}, \"constructor.prototype.ppMarker7f3a\", 'polluted')",
              "fixes": [
                "把 constructor / prototype 列入键名黑名单;递归合并前确认目标是普通对象(Object.getPrototypeOf 为 Object.prototype 或 null),不要递归进函数。",
                "对路径解析出的每一段做黑名单校验(__proto__、constructor、prototype 直接抛 TypeError),可参考 lodash >= 4.17.12 中 _.set 的修复方式。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            },
            {
              "strategy": "path",
              "vector": "__proto__",
              "pollutionType": "global-prototype",
              "severity": "high",
              "payload": "a.__proto__.ppMarker7f3a",
              "repro": "setPath({}, \"a.__proto__.ppMarker7f3a\", 'polluted')",
              "fixes": [
                "遍历来源对象时改用 Object.keys 只取自有键,并显式跳过 __proto__;或对赋值改用 Object.defineProperty,避免触发原型 setter。",
                "对路径解析出的每一段做黑名单校验(__proto__、constructor、prototype 直接抛 TypeError),可参考 lodash >= 4.17.12 中 _.set 的修复方式。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            },
            {
              "strategy": "path",
              "vector": "constructor.prototype",
              "pollutionType": "global-prototype",
              "severity": "high",
              "payload": "a.b.constructor.prototype.ppMarker7f3a",
              "repro": "setPath({}, \"a.b.constructor.prototype.ppMarker7f3a\", 'polluted')",
              "fixes": [
                "把 constructor / prototype 列入键名黑名单;递归合并前确认目标是普通对象(Object.getPrototypeOf 为 Object.prototype 或 null),不要递归进函数。",
                "对路径解析出的每一段做黑名单校验(__proto__、constructor、prototype 直接抛 TypeError),可参考 lodash >= 4.17.12 中 _.set 的修复方式。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            }
          ]
        },
        {
          "name": "getPath",
          "params": [
            "obj",
            "path"
          ],
          "arity": 2,
          "tested": 32,
          "findings": []
        },
        {
          "name": "defaultsDeep",
          "params": [
            "target",
            "sources"
          ],
          "arity": 1,
          "tested": 24,
          "findings": [
            {
              "strategy": "object",
              "vector": "__proto__",
              "pollutionType": "global-prototype",
              "severity": "high",
              "payload": "{\"__proto__\":{\"ppMarker7f3a\":1}}",
              "repro": "defaultsDeep({}, JSON.parse('{\"__proto__\":{\"ppMarker7f3a\":1}}'))",
              "fixes": [
                "遍历来源对象时改用 Object.keys 只取自有键,并显式跳过 __proto__;或对赋值改用 Object.defineProperty,避免触发原型 setter。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            },
            {
              "strategy": "object",
              "vector": "constructor.prototype",
              "pollutionType": "global-prototype",
              "severity": "high",
              "payload": "{\"constructor\":{\"prototype\":{\"ppMarker7f3a\":1}}}",
              "repro": "defaultsDeep({}, JSON.parse('{\"constructor\":{\"prototype\":{\"ppMarker7f3a\":1}}}'))",
              "fixes": [
                "把 constructor / prototype 列入键名黑名单;递归合并前确认目标是普通对象(Object.getPrototypeOf 为 Object.prototype 或 null),不要递归进函数。",
                "可直接替换为检测通过的安全版本 lib/object-utils.safe.js。"
              ]
            }
          ]
        },
        {
          "name": "isObject",
          "params": [
            "v"
          ],
          "arity": 1,
          "tested": 24,
          "findings": []
        },
        {
          "name": "isPlainObject",
          "params": [
            "v"
          ],
          "arity": 1,
          "tested": 24,
          "findings": []
        }
      ]
    },
    {
      "label": "safe",
      "file": "lib/object-utils.safe.js",
      "functions": [
        {
          "name": "merge",
          "params": [
            "target",
            "sources"
          ],
          "arity": 1,
          "tested": 24,
          "findings": []
        },
        {
          "name": "deepMerge",
          "params": [
            "target",
            "source"
          ],
          "arity": 2,
          "tested": 24,
          "findings": []
        },
        {
          "name": "deepClone",
          "params": [
            "obj"
          ],
          "arity": 1,
          "tested": 24,
          "findings": []
        },
        {
          "name": "setPath",
          "params": [
            "obj",
            "path",
            "value"
          ],
          "arity": 3,
          "tested": 32,
          "findings": []
        },
        {
          "name": "getPath",
          "params": [
            "obj",
            "path"
          ],
          "arity": 2,
          "tested": 32,
          "findings": []
        },
        {
          "name": "defaultsDeep",
          "params": [
            "target",
            "sources"
          ],
          "arity": 1,
          "tested": 24,
          "findings": []
        },
        {
          "name": "isObject",
          "params": [
            "v"
          ],
          "arity": 1,
          "tested": 24,
          "findings": []
        },
        {
          "name": "isPlainObject",
          "params": [
            "v"
          ],
          "arity": 1,
          "tested": 24,
          "findings": []
        }
      ]
    }
  ]
};
