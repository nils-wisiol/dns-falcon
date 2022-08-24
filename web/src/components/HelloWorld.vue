<template>
  <v-container>
    <v-row class="text-center">
      <v-col class="mb-4 mt-4">
        <h1 class="display-2 font-weight-bold mb-3">
          Post-Quantum DNSSEC with FALCON-512 and PowerDNS
        </h1>
      </v-col>
    </v-row>



    <v-row>
      <v-col
        class="mb-5"
        cols="12"
      >
        <h2 class="headline font-weight-bold mb-3">
          Make a query to our resolver
        </h2>
        <p class="subheading font-weight-regular">
          Send queries to our post-quantum enabled verifying resolver!
          To obtain responses signed with FALCON-512, query <code>A</code>, <code>AAAA</code>, and <code>TXT</code>
          records at <code>falcon.example.pq-dnssec.dedyn.io.</code> and <code>*.falcon.example.pq-dnssec.dedyn.io.</code>.
          To get classical signatures, try <code>rsasha256.example.pq-dnssec.dedyn.io.</code>,
          <code>ecdsa256.example.pq-dnssec.dedyn.io.</code>, <code>ed25519.example.pq-dnssec.dedyn.io.</code>, and the like.
        </p>
        <p class="subheading font-weight-regular">
          Queries will be sent from your browser using DNS-over-HTTPS to a PowerDNS recursor with FALCON-512 support.
          The recursor will query our PowerDNS authoritative DNS server (again, with FALCON-512 support), to get your
          reponse.
          The recursor will then validate the signature and send the result to your browser.
          All queries are send with the <code>DNSSEC_OK</code> flag (<code>+dnssec</code> in dig), so you will see
          <code>RRSIG</code> and <code>NSEC</code>/<code>NSEC3</code> records the the responses.
        </p>
        <p>
          For more information, please check out the code at
          <a
            href="https://github.com/nils-wisiol/dns-falcon"
            target="_blank"
          >GitHub</a>.
        </p>
      </v-col>
    </v-row>

    <v-row>
      <v-col>
        <v-row>
          <v-text-field
            v-model="qtype"
            filled
            label="Query type"
            type="text"
          ></v-text-field>
          <v-text-field
            v-model="qname"
            append-outer-icon="mdi-send"
            filled
            clear-icon="mdi-close-circle"
            clearable
            label="Enter a domain name"
            type="text"
            @click:append-outer="query"
          ></v-text-field>
        </v-row>
        <v-row v-if="working">
          <v-col>
            <div class="text-center"><v-progress-circular indeterminate color="primary"></v-progress-circular></div>
          </v-col>
        </v-row>
        <v-row v-if="err">
          <v-alert>{{err}}</v-alert>
        </v-row>
        <v-row v-if="!working && r_text">
          <code style="overflow: hidden"><span v-for="(l, index) in r_text" v-bind:key="index">{{l}}<br/></span></code>
        </v-row>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import {sendDohMsg} from 'dohjs'
import {RECURSION_DESIRED} from 'dns-packet'

  export default {
    name: 'HelloWorld',

    data: () => ({
      qtype: 'TXT',
      qname: 'falcon.example.pq-dnssec.dedyn.io',
      q: '',
      r_text: [],
      working: false,
      err: false,
    }),
    methods: {
      query: function () {
        this.working = true
        this.err = false
        this.q = {
            type: 'query',
            id: 0,
            flags: RECURSION_DESIRED,
            questions: [{
              type: this.qtype,
              name: this.qname,
            }],
            additionals: [{
              type: 'OPT',
              name: '.',
              udpPayloadSize: 4096,
              flags: 1 << 15, // DNSSEC_OK
            }]
        }
        sendDohMsg(this.q, 'https://pq-dnssec.dedyn.io/dns-query', 'GET', [], 1500)
          .then(r => {this.digest(r); this.working = false;})
          .catch(err => {this.err = err; this.working = false;})
      },
      digest: function (r) {
        this.r_text = []
        // this.r_text.push(r)

        // Header:
        // ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25078
        // ;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 2, ADDITIONAL: 1
        this.r_text.push(`;; ->>HEADER<<- opcode: ${r.opcode}, status: ${r.rcode}, id: ${r.id}`)
        let flags = []
        if (r.flag_qr) flags.push('qr')
        if (r.flag_aa) flags.push('aa')
        if (r.flag_tc) flags.push('tc')
        if (r.flag_rd) flags.push('rd')
        if (r.flag_ra) flags.push('ra')
        if (r.flag_z) flags.push('z')
        if (r.flag_ad) flags.push('ad')
        if (r.flag_cd) flags.push('cd')
        this.r_text.push(`;; flags: ${flags.join(' ')}; QUERY: ${r.questions.length}, ANSWER: ${r.answers.length}, AUTHORITY: ${r.authorities.length}, ADDITIONAL: ${r.additionals.length}`)
        this.r_text.push('')

        // Question
        this.r_text.push(';; QUESTION SECTION:')
        this.r_text.push(...this.render_section(r.questions))
        this.r_text.push('')

        // Answer
        this.r_text.push(';; ANSWER SECTION:')
        this.r_text.push(...this.render_section(r.answers))
        this.r_text.push('')

        // Authority
        if (r.authorities.length) {
          this.r_text.push(';; AUTHORITY SECTION:')
          this.r_text.push(...this.render_section(r.authorities))
          this.r_text.push('')
        }
      },
      render_section(s) {
        let full_section = []
        s.forEach((rrset) => {
          let full_rrset_txt = ''
          if (rrset.data) {
            full_rrset_txt = `${rrset.name} ${rrset.ttl} ${rrset.class} ${rrset.type} `
            if (rrset.type == 'RRSIG')
              full_rrset_txt += (
                  `${rrset.data.typeCovered} ${rrset.data.algorithm} ${rrset.data.labels} ${rrset.data.originalTTL} ` +
                  `${rrset.data.inception} ${rrset.data.expiration} ${rrset.data.keyTag} ${rrset.data.signersName} ` +
                  `${rrset.data.signature.toString('base64')}`
              )
            else if (rrset.type == 'TXT') {
              rrset.data.forEach((rr) => {
                full_rrset_txt += `"${rr.toString()}" `
              })
            } else if (rrset.type == 'A' || rrset.type == 'AAAA') {
              full_rrset_txt += rrset.data
            } else if (rrset.type == 'SOA') {
              // { "name": "falcon3.example", "type": "SOA", "ttl": 3600, "class": "IN", "flush": false,
              // "data": { "mname": "a.misconfigured.dns.server.invalid", "rname": "hostmaster.falcon3.example", "serial": 0, "refresh": 10800, "retry": 3600, "expire": 604800, "minimum": 3600 } }
              // a.misconfigured.dns.server.invalid. hostmaster.falcon.example.pq-dnssec.dedyn.io. 0 10800 3600 604800 3600
              full_rrset_txt += `${rrset.data.mname} ${rrset.data.rname} ${rrset.data.serial} ${rrset.data.refresh} ${rrset.data.retry} ${rrset.data.expire} ${rrset.data.minimum}`
            } else if (rrset.type == 'NSEC' || rrset.type == 'NSEC3') {
              full_rrset_txt += `${rrset.data.nextDomain} ${rrset.data.rrtypes.join(' ')}`
            } else {
              full_rrset_txt = rrset
            }
          } else {
            full_rrset_txt = `${rrset.name} ${rrset.class} ${rrset.type}`
          }
          full_section.push(full_rrset_txt)
        })
        return full_section
      }
    },
  }
</script>
