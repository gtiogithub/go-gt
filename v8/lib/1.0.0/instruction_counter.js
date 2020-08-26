// Copyright (C) 2017 go-gt authors
//
// This file is part of the go-gt library.
//
// the go-gt library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// the go-gt library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-gt library.  If not, see <http://www.gnu.org/licenses/>.
//
'use strict';

const module_path_prefix = (typeof process !== 'undefined') && (process.release.name === 'node') ? './' : '';
const esprima = require(module_path_prefix + 'esprima.js');
const console = require("console.js");

function traverse(object, visitor, master, injection_context_from_parent) {
    var key, child, parent, path;

    parent = (typeof master === 'undefined') ? [{
        node: null,
        key: ""
    }] : master;

    var injection_context = visitor.call(null, object, parent, injection_context_from_parent);
    if (injection_context === false) {
        return;
    }

    for (key in object) {
        if (object.hasOwnProperty(key)) {
            child = object[key];
            if (typeof child === 'object' && child !== null) {
                var injection_context_of_key = injection_context ? injection_context[key] : injection_context_from_parent;

                if (Array.isArray(object)) {
                    // ignore Array object in parents.
                    path = [];
                } else {
                    path = [{
                        node: object,
                        key: key
                    }];
                }
                path.push.apply(path, parent);
                traverse(child, visitor, path, injection_context_of_key);
            }
        }
    }
};

function traverseClass(object, visitor, master, context) {
    var key, child, parent, path;

    parent = (typeof master === 'undefined') ? [{
        node: null,
        key: ""
    }] : master;

    if (object.type == "ClassDeclaration") {
        if (object.id && object.id.type == "Identifier") {
            context.className = object.id.name;
        }
    }

    // visit children
    var indexes = Object.keys(object).sort(function (a, b) { return +a - +b; });
    for (let i = 0; i < indexes.length; i++) {
        const key = indexes[i];
        if (object.hasOwnProperty(key)) {
            child = object[key];
            if (typeof child === 'object' && child !== null) {
                if (Array.isArray(object)) {
                    // ignore Array object in parents.
                    path = [];
                } else {
                    path = [{
                        node: object,
                        key: key
                    }];
                }
                path.push.apply(path, parent);
                traverseClass(child, visitor, path, context);
            }
        }
    }

    // 
    visitor.call(null, object, parent, context);

    if (object.type == "ClassDeclaration") {
        context.className = null;
    }
};

function traverseContract(object, depth, context) {
    if (depth > 4) {
        return;
    }
    var key, child;
    const node = object;
    if (node.type == "AssignmentExpression") {
        if (node.left && node.left.type == "MemberExpression") {
            if (node.left.object && node.left.object.type != "Identifier" && node.left.object.name != "module") {
                return;
            }
            if (node.left.property && node.left.property.type != "Identifier" && node.left.property.name != "exports") {
                return;
            }
            if (node.right && node.right.type == "Identifier") {
                context.contractName = node.right.name;
                return;
            }
        }
    }

    // visite children
    for (var key in object) {
        if (object.hasOwnProperty(key)) {
            child = object[key];
            if (typeof child === 'object' && child !== null) {
                traverseContract(child, depth + 1, context);
            }
        }
    }
};

// key is the Expression, value is the count of instruction of the Expression.
const TrackingExpressions = {
    CallExpression: 8,
    AssignmentExpression: 3,
    BinaryExpression: 3,
    UpdateExpression: 3,
    UnaryExpression: 3,
    LogicalExpression: 3,
    MemberExpression: 4,
    NewExpression: 8,
    ThrowStatement: 6,
    MetaProperty: 4,
    ConditionalExpression: 3,
    YieldExpression: 6,
};

const InjectableExpressions = {
    ExpressionStatement: 1,
    VariableDeclaration: 1,
    ReturnStatement: 1,
    ThrowStatement: 1,
};

const InjectionType = {
    BEFORE_NODE: "BEFORE_NODE",
    AT_BEGINNING: "AT_BEGINNING",
    INNER_BEGINNING: "INNER_BEGINNING",
    INNER_BEGINNING_NOT_AND_OR: "INNER_BEGINNING_NOT_AND_OR",
};

const InjectionCodeGenerators = {
    CounterIncrFunc: function (value) {
        return "_instruction_counter.incr(" + value + ");";
    },
    BlockStatementBeginAndCounterIncrFunc: function (value) {
        if (value > 0) {
            return "{_instruction_counter.incr(" + value + ");"
        } else {
            return "{";
        }
    },
    BlockStatementEndAndCounterIncrFunc: function (value) {
        if (value > 0) {
            return "_instruction_counter.incr(" + value + ");}"
        } else {
            return "}";
        }
    },
    BlockStatementBeginAndCounterIncrFuncAndReturn: function (value) {
        if (value > 0) {
            return "{_instruction_counter.incr(" + value + "); return "
        } else {
            return "{return ";
        }
    },
    BeginInnerCounterIncrFunc: function (value) {
        return "_instruction_counter.incr(" + value + ") && (";
    },
    EndInnerCounterIncrFunc: function (value) {
        return ")";
    },
    CounterIncrFuncUsingNotAndLogicalOrFunc: function (value) {
        return "!_instruction_counter.incr(" + value + ") || ";
    },
};

function InjectionContext(node, type) {
    this.node = node;
    this.type = type;
};

function record_injection_info(injection_records, pos, value, injection_func) {
    var item = injection_records.get(pos);
    if (!item) {
        item = {
            pos: pos,
            value: 0,
            func: injection_func,
        };
        injection_records.set(pos, item);
    }
    item.value += value;
};

function processScript(source, strictDisallowUsage, on) {
    var injection_records = new Map();
    var funcs = [];
    var record_injection = function (pos, value, injection_func) {
        return record_injection_info(injection_records, pos, value, injection_func);
    };

    function ensure_block_statement(node) {
        if (!node || !node.type) {
            // not a valid node, ignore
            return;
        }

        if (!(node.type in {
            BlockStatement: "",
            IfStatement: "",
        })) {
            record_injection(node.range[0], 0, InjectionCodeGenerators.BlockStatementBeginAndCounterIncrFunc);
            record_injection(node.range[1], 0, InjectionCodeGenerators.BlockStatementEndAndCounterIncrFunc);
        }
    };

    function is_block_statement(node) {
        if (!node || !node.type) {
            // not a valid node, ignore
            return false;
        }

        if (!(node.type in {
            BlockStatement: "",
            IfStatement: "",
        })) {
            return true;
        }
        return false

    }

    function push_funcs(name) {
        if (name == "init") {
            return;
        }
        if (name == "constructor") {
            return;
        }
        funcs.push(name);
    }

    var ast = esprima.parseScript(source, {
        range: true,
        loc: true
    });

    var source_line_offset = 0;

    var classVisiter = function (node, parents, context) {
        if (node.type == "MethodDefinition") {
            if (context.contractName != null && context.contractName == context.className) {
                push_funcs(node.key.name);
            }
        } else if (node.type == "VariableDeclaration") {
            for (const key in node.declarations) {
                const decl = node.declarations[key];
                if (decl.type == "VariableDeclarator" && decl.id && decl.id.name == "pt") {
                    if (decl.init && decl.init.type == "ObjectExpression") {
                        decl.init.properties.forEach(ele => {
                            if (ele.value && ele.value.type == "FunctionExpression") {
                                push_funcs(ele.key.name);
                            }
                        });
                    }
                }
            }
        } else if (node.type == "AssignmentExpression") {
            if (node.left && node.left.type == "MemberExpression") {
                // console.log(node);
                // 
                if (node.left.object && node.left.object.type == "Identifier" && node.left.object.name == "module") {
                    // if (node.left.property && node.left.property.type != "Identifier" && node.left.property.name != "exports") {
                    //     return;
                    // }
                    // if (node.right && node.right.type == "Identifier") {
                    //     injection_context_from_parent.contractName = node.right.name;
                    //     console.log(node.right.name);
                    //     return;
                    // }
                    return;
                }
                if (node.left.object && node.left.object.type == "Identifier" && node.left.object.name == context.contractName) {
                    if (node.left.property && node.left.property.type == "Identifier" && node.left.property.name == "prototype") {
                        if (node.right.type == "ObjectExpression" && node.right.properties) {
                            node.right.properties.forEach(ele => {
                                if (ele.value && ele.value.type == "FunctionExpression") {
                                    push_funcs(ele.key.name);
                                }
                            });
                        } else if (node.right.type == "Identifier") {
                            if (context.ptName != node.right.name) {
                                context.ptName = node.right.name;
                            }
                        }
                    }
                    return;
                } else if (node.left.object && node.left.object.type == "MemberExpression") {
                    if (node.left.object.object.type == "Identifier" && node.left.object.object.name == context.contractName &&
                        node.left.object.property.type == "Identifier" && node.left.object.property.name == "prototype") {
                        const key = node.left.property.name;
                        if (node.right && node.right.type == "FunctionExpression") {
                            push_funcs(key);
                        }
                    }
                    return;
                }
            } else {
                // console.log("xxxx" + node);
            }
        } else if (node.type == "ObjectExpression") {
        } else {
        }
    };

    var visitor = function (node, parents, injection_context_from_parent) {
        // throw error when "_instruction_counter" was redefined in source.
        disallowRedefineOfInstructionCounter(node, parents, strictDisallowUsage);

        // 1. flag find the injection point, eg a Expression/Statement can inject code directly.
        if (node.type == "IfStatement") {
            ensure_block_statement(node.consequent);
            ensure_block_statement(node.alternate);
            return {
                "test": new InjectionContext(node.test, InjectionType.INNER_BEGINNING),
            };
        } else if (node.type == "ForStatement") {
            debugger
            ensure_block_statement(node.body);

            var pos = node.body.range[0];
            if (node.body.type === 'BlockStatement') {
                pos += 1;
            }
            record_injection(pos, 1, InjectionCodeGenerators.CounterIncrFunc);
            return {
                "init": new InjectionContext(node, InjectionType.BEFORE_NODE),
                "test": new InjectionContext(node.test, InjectionType.INNER_BEGINNING),
                "update": new InjectionContext(node.update, InjectionType.INNER_BEGINNING),
            };
        } else if (node.type == "ForInStatement") {
            ensure_block_statement(node.body);

            // because for in just call right once and iterate internal,
            // to keep inst const consistency with others, we manually add 1.
            var body = node.body;
            var pos = body.range[0];
            if (body.type === 'BlockStatement') {
                pos = body.range[0] + 1;
            }
            record_injection(pos, 2, InjectionCodeGenerators.CounterIncrFunc);

            return {
                "left": new InjectionContext(node, InjectionType.BEFORE_NODE),
                "right": new InjectionContext(node, InjectionType.BEFORE_NODE),
            };
        } else if (node.type == "ForOfStatement") {
            ensure_block_statement(node.body);

            // because for in just call right once and iterate internal,
            // to keep inst const consistency with others, we manually add 1.
            var body = node.body;
            var pos = body.range[0];
            if (body.type === 'BlockStatement') {
                pos = body.range[0] + 1;
            }
            record_injection(pos, 2, InjectionCodeGenerators.CounterIncrFunc);

            return {
                "left": new InjectionContext(node, InjectionType.BEFORE_NODE),
                "right": new InjectionContext(node, InjectionType.BEFORE_NODE),
            };
        } else if (node.type == "WhileStatement") {
            ensure_block_statement(node.body);
            var pos = node.body.range[0];
            if (node.body.type === 'BlockStatement') {
                pos += 1;
            }
            record_injection(pos, 1, InjectionCodeGenerators.CounterIncrFunc);
            return {
                "test": new InjectionContext(node.test, InjectionType.INNER_BEGINNING),
            };
        } else if (node.type == "DoWhileStatement") {
            ensure_block_statement(node.body);
            var pos = node.body.range[0];
            if (node.body.type === 'BlockStatement') {
                pos += 1;
            }
            record_injection(pos, 1, InjectionCodeGenerators.CounterIncrFunc);
            return {
                "test": new InjectionContext(node.test, InjectionType.INNER_BEGINNING),
            };
        } else if (node.type == "WithStatement") {
            ensure_block_statement(node.body);
            return {
                "object": new InjectionContext(node, InjectionType.BEFORE_NODE),
            };
        } else if (node.type == "SwitchStatement") {
            return {
                "discriminant": new InjectionContext(node, InjectionType.BEFORE_NODE),
            };
        } else if (node.type == "ArrowFunctionExpression") {
            var body = node.body;
            if (body.type !== 'BlockStatement') {
                record_injection(body.range[0], 0, InjectionCodeGenerators.BlockStatementBeginAndCounterIncrFuncAndReturn);
                record_injection(body.range[1], 0, InjectionCodeGenerators.BlockStatementEndAndCounterIncrFunc);

                // only return injection context when body is not in {};
                return {
                    "body": new InjectionContext(body, InjectionType.BEFORE_NODE),
                };
            }
        } else if (node.type == "ConditionalExpression") {
            return {
                "test": new InjectionContext(node.test, InjectionType.INNER_BEGINNING_NOT_AND_OR),
                "consequent": new InjectionContext(node.consequent, InjectionType.INNER_BEGINNING_NOT_AND_OR),
                "alternate": new InjectionContext(node.alternate, InjectionType.INNER_BEGINNING_NOT_AND_OR),
            };
        } else {

            // Other Expressions.
            var tracing_val = TrackingExpressions[node.type];
            if (!tracing_val) {
                // not the tracking expression, ignore.
                return;
            }

            // If no parent, apply default rule: BEFORE_NODE.
            var parent_node = parents[0].node;
            if (!parent_node) {
                record_injection(node.range[0], tracing_val, InjectionCodeGenerators.CounterIncrFunc);
                return;
            }

            var injection_type = null;
            var target_node = null;

            if (injection_context_from_parent) {
                target_node = injection_context_from_parent.node;
                injection_type = injection_context_from_parent.type;
            } else {
                injection_type = InjectionType.BEFORE_NODE;
            }

            if (!target_node) {
                if (node.type in InjectableExpressions) {
                    target_node = node;
                } else {
                    // searching parent to find the injection position.
                    for (var i = 0; i < parents.length; i++) {
                        var ancestor = parents[i];
                        if (ancestor.node.type in InjectableExpressions) {
                            target_node = ancestor.node;
                            break;
                        }
                    }
                }
            }

            var pos = -1;
            var generator = InjectionCodeGenerators.CounterIncrFunc;

            switch (injection_type) {
                case InjectionType.BEFORE_NODE:
                    pos = target_node.range[0];
                    break;
                case InjectionType.AT_BEGINNING:
                    if (target_node.type === 'BlockStatement') {
                        pos = target_node.range[0] + 1; // after "{".
                    } else {
                        pos = target_node.range[0]; // before statement start.
                    }
                    break;
                case InjectionType.INNER_BEGINNING:
                    pos = -1;
                    record_injection(target_node.range[0], tracing_val, InjectionCodeGenerators.BeginInnerCounterIncrFunc);
                    record_injection(target_node.range[1], tracing_val, InjectionCodeGenerators.EndInnerCounterIncrFunc);
                    break;
                case InjectionType.INNER_BEGINNING_NOT_AND_OR:
                    pos = target_node.range[0];
                    generator = InjectionCodeGenerators.CounterIncrFuncUsingNotAndLogicalOrFunc;
                    break;
                default:
                    throw new Error("Unknown Injection Type " + injection_type);
            }

            if (pos >= 0) {
                record_injection(pos, tracing_val, generator);
            }
        }
    };

    if (true) {
        var context = {
            className: null,
            constructor: null,
            isPrototype: false,
            ptName: null,
            contractName: null,
        };
        traverseContract(ast, 1, context);
        traverseClass(ast, classVisiter, [{
            node: null,
            key: ""
        }], context);
        if (context.ptName != null) {
            // traverseClass(ast, classVisiter, [{
            //     node: null,
            //     key: ""
            // }], context);
        }
    }
    traverse(ast, visitor);

    // generate traceable source.
    var ordered_records = Array.from(injection_records.values());
    ordered_records.sort(function (a, b) {
        return a.pos - b.pos;
    });

    var start_offset = 0,
        traceable_source = "";
    ordered_records.forEach(function (record) {
        traceable_source += source.slice(start_offset, record.pos);
        traceable_source += record.func(record.value);
        start_offset = record.pos;
    });
    traceable_source += source.slice(start_offset);

    //console.log("funcs ->", funcs);
    //console.log('-----------------------------------------------------------over');

    return {
        traceableSource: traceable_source,
        lineOffset: source_line_offset,
        funcs: JSON.stringify(funcs)
    };
};

// throw error when "_instruction_counter" was redefined.
function disallowRedefineOfInstructionCounter(node, parents, strictDisallowUsage) {
    if (node.type == 'Identifier') {
        if (node.name != '_instruction_counter') {
            return;
        }
    } else if (node.type == 'Literal') {
        if (node.value != '_instruction_counter') {
            return;
        }
    } else {
        return;
    }

    if (strictDisallowUsage) {
        throw new Error("redefine or use _instruction_counter are now allowed.");
    }

    var parent_node = parents[0].node;
    if (!parent_node) {
        return;
    }

    if (parent_node.type in {
        VariableDeclarator: "",
        FunctionDeclaration: "",
        FunctionExpression: "",
        ArrayPattern: "",
    }) {
        throw new Error("redefine _instruction_counter is now allowed.");
    }
};

exports["parseScript"] = esprima.parseScript;
exports["processScript"] = processScript;
