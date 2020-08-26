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

let isJsonString = function (obj) {
    try {
        if (typeof JSON.parse(obj) == "object") {
            return true;
        }
    } catch (e) {
    }
    return false;
}

var fieldNameRe = /^[a-zA-Z_$][a-zA-Z0-9_]+$/;

var combineStorageMapKey = function (fieldName, key) {
    //return "@" + fieldName + "[" + key + "]";
    return "@CTVD:" + fieldName + "|" + key;
};

var combineStorageVariableKey = function (fieldName) {
    return "@CTVD:" + fieldName + "|value";
};

var combineStorageMetaKey = function (fieldName) {
    return "@CTVM:" + fieldName;
};

var applyMapDescriptor = function (obj, descriptor) {
    descriptor = Object.assign({
        stringify: JSON.stringify,
        parse: JSON.parse
    }, descriptor || {});

    if (typeof descriptor.stringify !== 'function' || typeof descriptor.parse !== 'function') {
        throw new Error("descriptor.stringify and descriptor.parse must be function.");
    }

    Object.defineProperty(obj, "stringify", {
        configurable: false,
        enumerable: false,
        get: function () {
            return descriptor.stringify;
        }
    });

    Object.defineProperty(obj, "parse", {
        configurable: false,
        enumerable: false,
        get: function () {
            return descriptor.parse;
        }
    });
};

var applyFieldDescriptor = function (obj, fieldName, descriptor) {
    descriptor = Object.assign({
        stringify: JSON.stringify,
        parse: JSON.parse
    }, descriptor || {});

    if (typeof descriptor.stringify !== 'function' || typeof descriptor.parse !== 'function') {
        throw new Error("descriptor.stringify and descriptor.parse must be function.");
    }

    Object.defineProperty(obj, "__stringify__" + fieldName, {
        configurable: false,
        enumerable: false,
        get: function () {
            return descriptor.stringify;
        }
    });

    Object.defineProperty(obj, "__parse__" + fieldName, {
        configurable: false,
        enumerable: false,
        get: function () {
            return descriptor.parse;
        }
    });
};

var ContractStorage = function (handler) {
    var ns = new NativeStorage(handler);
    Object.defineProperty(this, "nativeStorage", {
        configurable: false,
        enumerable: false,
        get: function () {
            return ns;
        }
    });
};

var StorageMap = function (contractStorage, fieldName, descriptor) {
    if (!contractStorage instanceof ContractStorage) {
        throw new Error("StorageMap only accept instance of ContractStorage");
    }

    if (typeof fieldName !== "string" || fieldNameRe.exec(fieldName) == null) {
        throw new Error("StorageMap fieldName must match regex /^[a-zA-Z_$].*$/");
    }

    Object.defineProperty(this, "contractStorage", {
        configurable: false,
        enumerable: false,
        get: function () {
            return contractStorage;
        }
    });
    Object.defineProperty(this, "fieldName", {
        configurable: false,
        enumerable: false,
        get: function () {
            return fieldName;
        }
    });

    applyMapDescriptor(this, descriptor);
};


StorageMap.prototype = {
    del: function (key) {
        return this.contractStorage.del(combineStorageMapKey(this.fieldName, key));
    },
    get: function (key) {
        var val = this.contractStorage.rawGet(combineStorageMapKey(this.fieldName, key));
        if (val != null && val != "not found") {
            val = this.parse(val);
        }
        return val;
    },
    set: function (key, value) {
        var val = this.stringify(value);
        return this.contractStorage.rawSet(combineStorageMapKey(this.fieldName, key), val);
    }
};
StorageMap.prototype.put = StorageMap.prototype.set;
StorageMap.prototype.delete = StorageMap.prototype.del;


ContractStorage.prototype = {
    rawGet: function (key) {
        return this.nativeStorage.get(key);
    },
    rawSet: function (key, value) {
        var ret = this.nativeStorage.set(key, value);
        if (ret != 0) {

            throw new Error("set key " + key + " failed.:" + value);
        }
        return ret;
    },
    del: function (key) {
        var ret = this.nativeStorage.del(key);
        if (ret != 0) {
            throw new Error("del key " + key + " failed.");
        }
        return ret;
    },
    get: function (key) {
        var val = this.rawGet(key);
        console.log("CALL GET 2 !")
        console.log("get1111111:" + key + "value = " + val)
        if (isJsonString(val)) {
            val = JSON.parse(val);
        }
        console.log("get2:" + key + "value = " + val)
        return val;
    },
    set: function (key, value) {
        return this.rawSet(key, JSON.stringify(value));
    },
    defineProperty: function (obj, fieldName, inheritable, inheritField, descriptor) {
        if (!obj || !fieldName) {
            throw new Error("defineProperty requires at least two parameters.");
        }
        descriptor = Object.assign({ inheritable: inheritable, inheritField: inheritField, field: fieldName }, descriptor)
        var $this = this;
        Object.defineProperty(obj, fieldName, {
            configurable: false,
            enumerable: true,
            get: function () {
                var val = $this.rawGet(combineStorageVariableKey(fieldName));
                if (val != null) {
                    val = obj["__parse__" + fieldName](val);
                }
                return val;
            },
            set: function (val) {
                val = obj["__stringify__" + fieldName](val);
                return $this.rawSet(combineStorageVariableKey(fieldName), val);
            }
        });
        applyFieldDescriptor(obj, fieldName, descriptor);
        /*把合约定义的变量的descriptor信息写入到variables中，go中控制@CTD：fieldName 为 key,descriptor为value.key1,key2,..... 用"|"分割*/
        let ret = this.set(combineStorageMetaKey(fieldName), descriptor);
        if (ret != 0) {
            throw new Error("var_descriptor:", combineStorageMetaKey(fieldName) + " failed.");
        }
        return this;
    },
    defineProperties: function (obj, props) {
        if (!obj || !props) {
            throw new Error("defineProperties requires two parameters.");
        }
        for (const fieldName in props) {
            if (props[fieldName] == null) {
                this.defineProperty(obj, fieldName, false, "", {});
            } else {
                let inheritable = false;
                let inheritField = "";
                if (props[fieldName].hasOwnProperty("inheritable")) {
                    inheritable = props[fieldName]["inheritable"]
                }
                if (props[fieldName].hasOwnProperty("inheritField")) {
                    inheritField = props[fieldName]["inheritField"]
                }
                this.defineProperty(obj, fieldName, inheritable, inheritField, props[fieldName]);
            }
        }
        return this;
    },
    defineMapProperty: function (obj, fieldName, inheritable, inheritField, descriptor) {
        if (!obj || !fieldName) {
            throw new Error("defineMapProperty requires two parameters.");
        }
        descriptor = Object.assign({ inheritable: inheritable, inheritField: inheritField }, descriptor)
        var mapObj = new StorageMap(this, fieldName, descriptor);

        /*把合约定义的变量的descriptor信息写入到variables中，go中控制@CTD：fieldName|value 为 key,descriptor为value.key1,key2,..... 用"|"分割*/
        let ret = this.set(combineStorageMetaKey(fieldName), descriptor);
        if (ret != 0) {
            throw new Error("map_descriptor:", combineStorageMetaKey(fieldName) + " failed.");
        }
        Object.defineProperty(obj, fieldName, {
            configurable: false,
            enumerable: true,
            get: function () {
                return mapObj;
            }
        });
        return this;
    },
    defineMapProperties: function (obj, props) {
        if (!obj || !props) {
            throw new Error("defineMapProperties requires two parameters.");
        }

        for (const fieldName in props) {
            if (props[fieldName] == null) {
                this.defineProperty(obj, fieldName, false, "", {});
            } else {
                let inheritable = false;
                let inheritField = "";
                if (props[fieldName].hasOwnProperty("inheritable")) {
                    inheritable = props[fieldName]["inheritable"]
                }
                if (props[fieldName].hasOwnProperty("inheritField")) {
                    inheritField = props[fieldName]["inheritField"]
                }
                this.defineMapProperty(obj, fieldName, props[fieldName]["inheritable"], props[fieldName]["inheritField"], props[fieldName]);
            }
        }
        return this;
    },
    defineInheritProperties: function (obj, address) {
        if (!obj || !address) {
            throw new Error("defineInheritProperties requires two parameters.");
        }
        if (typeof (address) != "string") {
            throw ("defineInheritProperties : contract address should be a string");
        }
        if (address != "null") {
            //
            // var src = _native_blockchain.getContractSource(address);
            // if (src == null) {
            //     throw ("defineInheritProperties: no contract at this address");
            // }
        }
        /*把继承的合约地址写到合约账户的variables中，go中处理key规则,只传继承的合约地址 以CTM开头 */
        let ret = this.nativeStorage.sca(address);
        if (ret != 0) {
            console.log("ret:", ret)
            throw new Error("set StorageSetContractAddrFunc failed.");
        }
        return this;
    },
};

ContractStorage.prototype.put = ContractStorage.prototype.set;
ContractStorage.prototype.delete = ContractStorage.prototype.del;

var lcs = new ContractStorage(_native_storage_handlers.lcs);
var obj = { ContractStorage: ContractStorage };
Object.defineProperty(obj, "lcs", {
    configurable: false,
    enumerable: false,
    get: function () {
        return lcs;
    }
});


module.exports = Object.freeze(obj);