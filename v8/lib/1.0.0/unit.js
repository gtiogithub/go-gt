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

'use strict';
var util = require('util.js');

const unitMap = {
    'none': '0',
    'None': '0',
    'nc': '1',
    'nC': '1',
    'uc': '100',
    'uC': '100',
    'mc': '10000',
    'mC': '10000',
    'cc': '1000000',
    'cC': '1000000',
    'c': '100000000',
    'C': '100000000',
};

function unitValue(unit) {
    unit = unit ? unit.toLowerCase() : 'c';
    var unitValue = unitMap[unit];
    if (unitValue === undefined) {
        throw new Error('The unit undefined, please use the following units:' + JSON.stringify(unitMap, null, 2));
    }
    return new BigNumber(unitValue, 10);
};

function toBasic(number, unit) {
    return util.toBigNumber(number).times(unitValue(unit));
};

function fromBasic(number, unit) {
    return util.toBigNumber(number).dividedBy(unitValue(unit));
};

function cToBasic(number) {
    return util.toBigNumber(number).times(unitValue("c"));
};

module.exports = {
    toBasic: toBasic,
    fromBasic: fromBasic,
    cToBasic: cToBasic
};