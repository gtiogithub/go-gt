'use strict';

let Owner = function(obj){
    this.address = "";
    this.parse(obj);
}
Owner.prototype = {
    toString:function(){
        return this.address;
    },
    parse:function(obj) {
        if (typeof obj != "undefined"){
            this.address = obj;
        }
    },
    isOwner:function () {
        if (this.address === Blockchain.transaction.from){
            return true;
        }
        return false;
    }
}
let Nodes = function(obj) {
    this.nodes = {};
    this.parse(obj);
}

Nodes.prototype = {
    toString:function () {
        return JSON.stringify(this.nodes);
    },
    parse:function (obj) {
        if (typeof obj != "undefined") {
            var data = JSON.parse(obj);
            for (var key in data) {
                this.nodes[key] = new BigNumber(data[key]);
            }
        }
    },
    remove:function(key){
        delete this.nodes[key];
    },
    get: function (key) {
        return this.nodes[key];
    },

    set: function (key, value) {
        this.nodes[key] = new BigNumber(value);
    }
}

let SystemContract = function () {

    LocalContractStorage.defineProperties(this,{
        _name: null,
        _owner:{
            parse: function (value) {
                return new Owner(value);
            },
            stringify: function (o) {
                return o.toString();
            }
        },
        blockInterval:null,
        superNodeCount:null,
        witnessCount:null,
        perContractTxFee:{
            parse:function(value) {
                return new BigNumber(value)
            },
            stringify:function(o) {
                return o.toString(10);
            }
        },
        deployContractMinVolume:null,
        floatingCycle:null,
        superNodes:{
            parse: function (value) {
                return new Nodes(value);
            },
            stringify: function (o) {
                return o.toString();
            }
        }
    });
    LocalContractStorage.defineMapProperty(this,"variables");
}

SystemContract.prototype = {
    init:function(name,address,args){
        this._name = name;
        if (typeof address == "undefined") {
            throw new Error("invalid address argument.");
        }
        if (Blockchain.verifyAddress(address) == 0) {
            throw new Error("invalid address.");
        }
        this._owner = new Owner(address)

        if (typeof args == "undefined") {
            throw new Error("invalid contract arguments.");
        }


        this.perContractTxFee = new BigNumber(args.perContractTxFee);
        this.blockInterval = args.blockInterval;
        this.superNodeCount = args.superNodeCount;
        this.witnessCount = args.witnessCount;
        this.deployContractMinVolume = args.deployContractMinVolume;
        this.floatingCycle = args.floatingCycle;

        let tempSuperNodes = new Nodes();
        if (typeof args.superNodes != "undefined" && args.superNodes.length > 0) {
            for (var i =0 ;i < args.superNodes.length;i++) {
                tempSuperNodes.set(args.superNodes[i].address,args.superNodes[i].value);
            }
        }
        this.superNodes = tempSuperNodes;

        if (typeof args.variables != "undefined" && args.variables.length > 0 ) {
            for (var i =0 ;i < args.variables.length;i++) {
                this.variables.set(args.variables[i].name,args.variables[i].value);
            }
        }
    },
    name: function () {
        return this._name;
    },
    getSuperNodes:function () {
        let result = new String("");
        for (let key in this.superNodes.nodes) {
            result = result.concat(key, ":", this.superNodes.get(key).toString(10), ",");
        }
        return result;
    },
    getBlockInterval:function() {
        return this.blockInterval;
    },
    getWitnessCount:function() {
        return this.witnessCount;
    },
    getDeployContractMinVolume:function() {
        return this.deployContractMinVolume;
    },
    getPerContractTxFee:function() {
        return this.perContractTxFee;
    },
    getVariables: function(key){
        let value = this.variables.get(key);
        if (value != null) {
            return value
        }
        return "";
    },
    getMaxSuperNodeCount:function() {
        return this.superNodeCount;
    },
    getCurrentSuperNodeCount:function() {
        let i = 0;
        for (let key in this.superNodes.nodes) {
            i++
        }
        return i
    },
    getFloatingCycle:function() {
        return this.floatingCycle;
    },
    modifyFloatingCycle : function(value) {
        if (typeof value != "number" || value <= 1) {
            throw new Error("invalid argument.");
        }
        if(this._owner.isOwner()){
            let oldValue = this.floatingCycle;
            this.floatingCycle = value;
            Event.Trigger(this.name(), {
                status: true,
                attribute: "floatingCycle",
                old_value: oldValue,
                new_value: value
            });
        } else {
            throw new Error("modify cycle failed.");
        }
    },
    modifyBlockInterval: function (value) {
        if(typeof value != "number" || value <= 0) {
            throw new Error("invalid argument.")
        }
        if (this._owner.isOwner()){
            let oldValue = this.blockInterval;
            this.blockInterval = value
            Event.Trigger(this.name(), {
                status: true,
                attribute: "BlockInterval",
                old_value: oldValue,
                new_value: value
            });
        } else {
            throw new Error("modify block interval failed.");
        }

    },
    addSuperNodes:function(address,value) {
        if (this._owner.isOwner()) {
            if (this.superNodes.get(address)) {
                throw new Error("Add a repeat address.");
            }
            if (Blockchain.verifyAddress(address) == 0) {
                throw new Error("invalid address.");
            }
            value = new BigNumber(value);
            if (value.lt(0)) {
                throw new Error("invalid freeze value.");
            }
            if (this.getCurrentSuperNodeCount() == this.superNodeCount) {
                throw new Error("The number of super nodes has reached its limit.");
            }

            let nodes = this.superNodes;
            nodes.set(address,value);
            this.superNodes = nodes;
            Event.Trigger(this.name(), {
                status: true,
                attribute: "SuperNodes",
                operate: "Add",
                content:{"address":address,"value":value.toString(10)}
            });
        } else {
            throw new Error("Add Super Node failed.");
        }
    },
    removeSuperNodes:function(address) {
        if (this._owner.isOwner()) {
            if (!this.superNodes.get(address)) {
                throw new Error(" Non-supernodes cannot be removed.");
            }
            if (Blockchain.verifyAddress(address) == 0) {
                throw new Error("invalid address.");
            }

            let nodes = this.superNodes;
            nodes.remove(address)
            this.superNodes = nodes;
            Event.Trigger(this.name(), {
                status: true,
                attribute: "SuperNodes",
                operate: "Remove",
                content:{"address":address}
            });
        } else {
            throw new Error("Remove Super Node failed.");
        }
    },
    modifySuperNodeCount: function(value) {
        let minCount = this.getCurrentSuperNodeCount();
        if (typeof value != "number" || value < minCount) {
            throw new Error("invalid argument.");
        }
        if(this._owner.isOwner()){
            let oldValue = this.superNodeCount;
            this.superNodeCount = value;
            Event.Trigger(this.name(), {
                status: true,
                attribute: "superNodeCount",
                old_value: oldValue,
                new_value: value
            });
        } else {
            throw new Error("modify super node count failed.")
        }
    },
    modifyWitnessCount: function(value){
        if (typeof value != "number" || value < 3 || value % 3 != 0){
            throw new Error("invalid argument.");
        }
        if(this._owner.isOwner()){
            let oldValue = this.witnessCount;
            this.witnessCount = value;
            Event.Trigger(this.name(), {
                status: true,
                attribute: "witnessCount",
                old_value: oldValue,
                new_value: value
            });
        } else {
            throw new Error("modify witness count failed.");
        }
    },
    modifyPerContractTxFee: function(value) {
        value = new BigNumber(value)
        if (value.lt(0)) {
            throw new Error("invalid argument.");
        }
        if(this._owner.isOwner()){
            let oldValue = this.perContractTxFee;
            this.perContractTxFee = value;
            Event.Trigger(this.name(), {
                status: true,
                attribute: "perContractTxFee",
                old_value: oldValue.toString(10),
                new_value: value.toString(10)
            });
        } else {
            throw new Error("modify per contract transaction failed.");
        }
    },
    modifyDeployContractMinVolume: function(value) {
        if (typeof value != "number" || value < 0) {
            throw new Error("invalid argument.");
        }
        if(this._owner.isOwner()){
            let oldValue = this.deployContractMinVolume;
            this.deployContractMinVolume = value;
            Event.Trigger(this.name(), {
                status: true,
                attribute: "deployContractMinVolume",
                old_value: oldValue,
                new_value: value
            });
        } else {
            throw new Error("modify deploy contract min volume failed.");
        }
    },
    setVariables: function(key,value){
        if (this._owner.isOwner()) {
            this.variables.set(key, value);
        }else {
            throw new Error("set ["+key+"] variable failed.");
        }
    }
};

module.exports = SystemContract;