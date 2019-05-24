package com.comcast.cdn.traffic_control.traffic_router.core.ds;

/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

public class LetsEncryptDnsChallenge {
    @JsonProperty
    private String fqdn;

    @JsonProperty
    private String record;

    public String getFqdn() {
        return fqdn;
    }

    public void setFqdn(final String fqdn) {
        this.fqdn = fqdn;
    }

    public String getRecord() {
        return record;
    }

    public void setRecord(final String record) {
        this.record = record;
    }

    @Override
    @SuppressWarnings("PMD")
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LetsEncryptDnsChallenge that = (LetsEncryptDnsChallenge) o;
        return Objects.equals(fqdn, that.fqdn) &&
                Objects.equals(record, that.record);
    }

    @Override
    @SuppressWarnings("PMD")
    public int hashCode() {
        return Objects.hash(fqdn, record);
    }
}
