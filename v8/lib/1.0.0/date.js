// Copyright (C) 2018 go-gt authors
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


var GtDate = (function(ProtoDate) {

    function GtDate() {
        if (!Blockchain) {
            throw new Error("'Blockchain' is not defined.");
        }
        if (!Blockchain.block) {
            throw new Error("'Blockchain.block' is not defined.");
        }
    
        var date = new(Function.prototype.bind.apply(ProtoDate, [ProtoDate].concat(Array.prototype.slice.call(arguments))))();
        if (arguments.length == 0) {
            // unit of timestamp is second
            date.setTime(Blockchain.block.timestamp * 1000);
        }
        Object.setPrototypeOf(date, GtDate.prototype);
        return date;
    }
    GtDate.now = function() {
        return new GtDate().getTime();
    }
    GtDate.UTC = function() {
        return ProtoDate.UTC.apply(null, Array.prototype.slice.call(arguments));
    }
    GtDate.parse = function(dateString) {
        return ProtoDate.parse(dateString);
    }

    GtDate.prototype.getYear = function() {
        throw new Error("Deprecated!");
    }
    GtDate.prototype.setYear = function() {
        throw new Error("Deprecated!");
    }

    GtDate.prototype.toLocaleDateString = function() {
        var tmp = new ProtoDate.prototype.constructor(this.getTime());
        return ProtoDate.prototype.toLocaleDateString.apply(tmp, Array.prototype.slice.call(arguments));
    }

    GtDate.prototype.toLocaleTimeString = function() {
        var tmp = new ProtoDate.prototype.constructor(this.getTime());
        return ProtoDate.prototype.toLocaleTimeString.apply(tmp, Array.prototype.slice.call(arguments));
    }

    GtDate.prototype.toLocaleString = function() {
        var tmp = new ProtoDate.prototype.constructor(this.getTime());
        return ProtoDate.prototype.toLocaleString.apply(tmp, Array.prototype.slice.call(arguments));
    }

    GtDate.prototype = new Proxy(GtDate.prototype, {
        getPrototypeOf: function(target) {
            throw new Error("Unsupported method!");
        },
    });

    Object.setPrototypeOf(GtDate.prototype, ProtoDate.prototype);
    return GtDate;
})(Date);

module.exports = GtDate;