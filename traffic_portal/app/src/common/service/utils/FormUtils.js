/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

var FormUtils = function() {

    this.hasError = function(input) {
        return input && !input.$focused && input.$invalid;
    };

    this.oneInputHasError = function(input1, input2) {
        var input = [input1, input2];
        for(var i = 0; i < input.length; i++) {
            if (!this.hasError(input[i])) {
                return false;
            }
        }
        return true;
    };

    this.hasPropertyError = function(input, property) {
        return input && !input.$focused && input.$error[property];
    };

    this.oneInputHasPropertyError = function(property, input1, input2) {
        var input = [input1, input2];
        for(var i = 0; i < input.length; i++) {
            if (!this.hasPropertyError(input[i], property)) {
                return false;
            }
        }
        return true;
    };

};

FormUtils.$inject = [];
module.exports = FormUtils;
