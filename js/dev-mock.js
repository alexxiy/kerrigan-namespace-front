// Test data in place of the registrar, for working on the interface without a backend.
//
// js/app.js imports this file only on a local copy of the app opened with ?mock=1 (see
// mockModeRequested() there). The site never loads it. While it is installed, every request
// to the registrar is answered here, a request it has no answer for gets a 404 instead of
// going out, and a label in the corner of the page says test data is on.

export function installMock({ apiBase, getZones, getCachedPublicKey }) {
    const label = document.createElement('div');
    label.textContent = 'Test data (?mock=1): nothing is sent to the registrar';
    Object.assign(label.style, {
        position: 'fixed', left: '8px', bottom: '8px', zIndex: '10000', padding: '4px 10px',
        borderRadius: '6px', background: '#b45309', color: '#fff', pointerEvents: 'none',
        font: '600 12px/1.5 Inter, system-ui, sans-serif',
    });
    document.body.appendChild(label);

    const originalFetch = window.fetch;
    window.fetch = async function(input, init) {
        const url = typeof input === 'string' ? input : input.url;

        // 0. Payment address, network and the confirmation counts the registrar waits for
        //    (the local registrar config's thresholds, so they differ from the 40/120 fallback)
        if (url.includes('/v1.0/getPaymentAddress')) {
            return new Response(JSON.stringify({
                response: {
                    address: "ks1mockpaymentaddress",
                    network: "mainnet",
                    payment_confirmations: 5,
                    refund_confirmations: 10,
                    chainlock_confirmations: 2,
                    zones: getZones(),
                    max_count: 100
                }
            }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }

        // The update price check serves, by label length as the mock prices table below has it,
        // and a free name already paid for by someone else: one starting with "pending"
        const mockCheckExtras = (domain, isTaken) => ({
            update_price: (8 - Math.min(domain.indexOf('.'), 7)) * 100000000,
            ...(isTaken ? {} : { reg_pending: domain.startsWith('pending') })
        });

        // 1. Check Domain (GET /v1.0/check/{domain})
        if (url.includes('/v1.0/check/') && (!init || init.method === 'GET')) {
            let domain = url.substring(url.indexOf('/check/') + 7);
            const queryIdx = domain.indexOf('?');
            if (queryIdx !== -1) {
                domain = domain.substring(0, queryIdx);
            }
            const isListed = domain.startsWith('listed') || domain.startsWith('selling');
            const isTaken = isListed || domain.startsWith('taken') || domain.startsWith('alice');
            
            return new Response(JSON.stringify({
                response: {
                    exists: isTaken,
                    price: isListed ? "25000000000" : (isTaken ? "0" : (domain.length < 9 ? "15000000000" : "1500000000")),
                    ...mockCheckExtras(domain, isTaken)
                }
            }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }

        // 2. Poll Transaction Status or Availability Check (POST /v1.0/check/{domain})
        if (url.includes('/v1.0/check/') && init && init.method === 'POST') {
            let bodyData = {};
            if (init.body) {
                try {
                    bodyData = JSON.parse(init.body);
                } catch (e) {}
            }
            
            if (bodyData && bodyData.with_pubkey) {
                let domain = url.substring(url.indexOf('/check/') + 7);
                const queryIdx = domain.indexOf('?');
                if (queryIdx !== -1) {
                    domain = domain.substring(0, queryIdx);
                }
                const isListed = domain.startsWith('listed') || domain.startsWith('selling');
                const isTaken = isListed || domain.startsWith('taken') || domain.startsWith('alice');
                
                let pubkey = null;
                const accountStr = localStorage.getItem('kerrigan_encrypted_account');
                if (accountStr) {
                    try {
                        const data = JSON.parse(accountStr);
                        pubkey = data.pubKeyHex;
                    } catch (e) {}
                }
                if (!pubkey) {
                    pubkey = "mockPubKeyHex";
                }
                
                return new Response(JSON.stringify({
                    response: {
                        exists: isTaken,
                        price: isListed ? "25000000000" : (isTaken ? "0" : (domain.length < 9 ? "15000000000" : "1500000000")),
                        pubkey: pubkey,
                        ...mockCheckExtras(domain, isTaken)
                    }
                }), { status: 200, headers: { 'Content-Type': 'application/json' } });
            } else {
                const mockConfs = parseInt(sessionStorage.getItem('mock_confs') || '0') + 1;
                sessionStorage.setItem('mock_confs', mockConfs.toString());
                
                let status = 0; // Confirming
                if (mockConfs >= 5) {
                    status = 5; // Success
                    sessionStorage.removeItem('mock_confs');
                }
                
                return new Response(JSON.stringify({
                    response: {
                        status: status,
                        confirmations: mockConfs,
                        seconds: 15,
                        tx_id: "mock_tx_id_123456789"
                    }
                }), { status: 200, headers: { 'Content-Type': 'application/json' } });
            }
        }

        // 3. Get Marketplace or My Domains (POST /v1.0/domains), with the registrar's list
        //    options: sort, order, zone, status, a search with a dot, the echo of what was
        //    applied, every owner on the marketplace, and its `next`/`after` paging
        if (url.includes('/v1.0/domains') && !url.includes('/v1.0/domains/') && init && init.method === 'POST') {
            const body = JSON.parse(init.body);
            const reply = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: { 'Content-Type': 'application/json' } });
            const isMy = body.type === 'my';
            const page = body.page || 1;
            const count = body.count || 20;
            const sort = body.sort || 'name';
            const order = body.order || 'asc';
            const zone = body.zone || '';
            const status = body.status || 'all';
            if (!['name', 'price', isMy ? 'updated' : 'listed'].includes(sort) || !['asc', 'desc'].includes(order) ||
                (zone !== '' && !getZones().includes(zone)) ||
                !(isMy ? ['all', 'listed', 'not_listed'] : ['all', 'listed']).includes(status)) {
                return reply({ error: { error_message: 'One or several params provided have wrong value' } });
            }
            // The update price by label length, as the mock prices table below has it
            const mockUpdPrice = (domain) => (8 - Math.min(domain.indexOf('.'), 7)) * 100000000;

            let list;
            if (isMy) {
                list = [
                    { domain: "test-identity.krgn", address: "ks1mockaddress1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno", price: 0, updated_ts: 1761900000 },
                    { domain: "cool-krgn-alias.secure", address: "ks1anothermockaddress1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefgh", price: 0, updated_ts: 1761800000 },
                    { domain: "on-sale-domain.safe", address: "ks1qxyanothermockaddress987654", price: 25000000000, updated_ts: 1762000000 },
                    { domain: "alex.private", address: "ks1mockprivateaddress1234567890", price: 4000000000, updated_ts: 1761700000 },
                    { domain: "zeta.kerrigan", address: "ks1mockzetaaddress1234567890", price: 4000000000, updated_ts: 1761600000 },
                    { domain: "home.safe", address: "ks1mockhomeaddress1234567890", price: 0, updated_ts: 1761500000 }
                ].map(item => ({ ...item, tx_price: mockUpdPrice(item.domain) }));
            } else {
                const named = [
                    { domain: "crypto.kerrigan", price: 15000000000, pubkey: "eb4acf26de7fd06e68b94f4c8fa65f244f2e0dce8e438212ca70b27d216dd098" },
                    { domain: "wallet.private", price: 35000000000, pubkey: "3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53" },
                    { domain: "anonymous.secure", price: 80000000000, pubkey: "eb4acf26de7fd06e68b94f4c8fa65f244f2e0dce8e438212ca70b27d216dd098" },
                    { domain: "nodes.safe", price: 5000000000, pubkey: "99aa887766554433221100" },
                    { domain: "payment.krgn", price: 12000000000, pubkey: "eb4acf26de7fd06e68b94f4c8fa65f244f2e0dce8e438212ca70b27d216dd098" },
                    { domain: "privacy.private", price: 45000000000, pubkey: "2233445566778899" },
                    { domain: "shielded.secure", price: 99000000000, pubkey: "3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53" },
                    { domain: "backup.safe", price: 3000000000, pubkey: "8877665544332211" }
                ];
                const ownKey = getCachedPublicKey();
                if (ownKey) {
                    named.push({ domain: "my-selling-domain.krgn", price: 25000000000, pubkey: ownKey });
                    named.push({ domain: "premium.safe", price: 150000000000, pubkey: ownKey });
                }
                // Filler up to 125 listings, in every zone, with prices that repeat so the
                // name tie-break shows
                for (let i = 1; named.length < 125; i++) {
                    named.push({
                        domain: `dummy${i}.${getZones()[i % getZones().length]}`,
                        price: (10 + (i * 7) % 50) * 100000000,
                        pubkey: "dummy_pubkey_hex"
                    });
                }
                list = named.map((item, i) => ({ ...item, tx_price: mockUpdPrice(item.domain), listed_ts: 1762000000 - i * 3600 }));
            }

            // "alex", "alex.ke", "alex.kerrigan", ".krgn": the label part anywhere in the label, the
            // zone part the start of the zone
            const query = (body.search || '').toLowerCase();
            const dot = query.indexOf('.');
            const label = (dot === -1 ? query : query.substring(0, dot)).replace(/[^a-z0-9-]/g, '');
            const zonePart = dot === -1 ? '' : query.substring(dot + 1).replace(/[^a-z]/g, '');
            list = list.filter(item => {
                const [itemLabel, itemZone] = item.domain.split('.');
                return itemLabel.includes(label) && itemZone.startsWith(zonePart) &&
                    (!zone || itemZone === zone) &&
                    !(isMy && status === 'listed' && item.price === 0) &&
                    !(status === 'not_listed' && item.price !== 0);
            });

            const dir = order === 'asc' ? 1 : -1;
            const byName = (a, b) => (a.domain < b.domain ? -1 : (a.domain > b.domain ? 1 : 0));
            const valueOf = (item) => ({ price: item.price, updated: item.updated_ts, listed: item.listed_ts }[sort]);
            list.sort((a, b) => {
                if (sort === 'name') return dir * byName(a, b);
                // In a user's own list, the names not on sale come last in both price orders
                if (isMy && sort === 'price' && (a.price === 0) !== (b.price === 0)) return a.price === 0 ? 1 : -1;
                return (valueOf(a) - valueOf(b)) * dir || byName(a, b);
            });

            let start = (page - 1) * count;
            if (!isMy && body.after) {
                const cursor = JSON.parse(atob(body.after.replace(/-/g, '+').replace(/_/g, '/')));
                start = list.findIndex(item => item.domain === cursor[cursor.length - 1]) + 1;
            }
            const domains = list.slice(start, start + count);
            const out = { count: list.length, sort, order, zone, status, min_price: null, max_price: null, domains };
            if (!isMy) {
                const last = domains[domains.length - 1];
                out.next = (last && start + count < list.length)
                    ? btoa(JSON.stringify([sort, order, ...(sort === 'name' ? [] : [valueOf(last)]), last.domain]))
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
                    : null;
            }
            return reply({ response: out });
        }

        // 4. Remove domain from sale (POST /v1.0/domains/remove)
        if (url.includes('/v1.0/domains/remove') && init && init.method === 'POST') {
            return new Response(JSON.stringify({ response: { success: true } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }

        // 5. Get My Names (GET /v1.0/names/)
        if (url.includes('/v1.0/names/') && (!init || init.method === 'GET')) {
            return new Response(JSON.stringify({
                response: {
                    names: [
                        { name: "test-identity.krgn", address: "ks1mockaddress1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno" },
                        { name: "cool-krgn-alias.secure", address: "ks1anothermockaddress1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefgh" }
                    ]
                }
            }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }

        // 6. Get Prices (POST /v1.0/prices)
        if (url.includes('/v1.0/prices') && init && init.method === 'POST') {
            const body = JSON.parse(init.body);
            const upd = { "1": 700000000, "2": 600000000, "3": 500000000, "4": 400000000, "5": 300000000, "6": 200000000, "7": 100000000 };
            const reg = { "1": 70000000000, "2": 60000000000, "3": 50000000000, "4": 40000000000, "5": 30000000000, "6": 20000000000, "7": 1500000000 };
            const table = { upd, reg, all: { reg, upd } }[body.type];
            if (table) {
                return new Response(JSON.stringify({ response: table }), { status: 200, headers: { 'Content-Type': 'application/json' } });
            }
        }
        
        // 7. Get or Withdraw Balance (POST /v1.0/balance)
        if (url.includes('/v1.0/balance') && init && init.method === 'POST') {
            const body = JSON.parse(init.body);
            if (body.action === 'get') {
                const mockBalance = window.lastMockBalance !== undefined ? window.lastMockBalance : "410000000";
                return new Response(JSON.stringify({
                    response: {
                        balance: mockBalance,
                        fee: 5,
                        min_withdrawal: 52631579
                    }
                }), { status: 200, headers: { 'Content-Type': 'application/json' } });
            } else if (body.action === 'withdraw') {
                window.lastMockBalance = "0.00000000";
                return new Response(JSON.stringify({
                    response: 1
                }), { status: 200, headers: { 'Content-Type': 'application/json' } });
            }
        }

        // 8. Transactions list (POST /v1.0/transactions)
        if (url.includes('/v1.0/transactions') && init && init.method === 'POST') {
            const body = JSON.parse(init.body);
            const page = body.page || 1;
            const count = body.count || 10;
            const type = body.type;

            if (type === 'in') {
                const allIncomingTx = [
                    {
                        domain_name: "zeta.kerrigan",
                        op: "LST",
                        price: 4000000000,
                        confirmations: 5,
                        status: 5,
                        tx_id: "f15b49dd7ce4830b2fbc696b3e2b0538d55ba22efd622674b0e4af74586e32b1",
                        memo: "KNS:1:LST:zeta.kerrigan:4000000000:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469310354:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a3dd57547d26a75c13e29b508d359bc16dde463ce8a1ec08a3ada9f4c1ad178b04"
                    },
                    {
                        domain_name: "hotel.secure",
                        op: "REG",
                        confirmations: 5,
                        status: 5,
                        tx_id: "e95b49dd7ce4830b2fbc696b3e2b0538d55ba22efd622674b0e4af74586e32b1",
                        memo: "KNS:1:REG:hotel.secure:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469310354:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a3dd57547d26a75c13e29b508d359bc16dde463ce8a1ec08a3ada9f4c1ad178b04"
                    },
                    {
                        domain_name: "moto321.private",
                        op: "REG",
                        confirmations: 5,
                        status: 5,
                        tx_id: "10ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189d1",
                        memo: "KNS:1:REG:moto321.private:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "crypto-wallet.kerrigan",
                        op: "REG",
                        confirmations: 5,
                        status: 0,
                        tx_id: "20ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189d2",
                        memo: "KNS:1:REG:crypto-wallet.kerrigan:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "anonymous.secure",
                        op: "REG",
                        confirmations: 10,
                        status: 1,
                        tx_id: "30ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189d3",
                        memo: "KNS:1:REG:anonymous.secure:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "my-domain.safe",
                        op: "REG",
                        confirmations: 20,
                        status: 2,
                        tx_id: "40ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189d4",
                        memo: "KNS:1:REG:my-domain.safe:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "payment-gate.krgn",
                        op: "REG",
                        confirmations: 20,
                        status: 3,
                        tx_id: "50ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189d5",
                        memo: "KNS:1:REG:payment-gate.krgn:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "privacy-first.private",
                        op: "REG",
                        confirmations: 20,
                        status: 4,
                        tx_id: "60ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189d6",
                        memo: "KNS:1:REG:privacy-first.private:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "orphaned-test.secure",
                        op: "REG",
                        confirmations: 0,
                        status: 6,
                        tx_id: "70ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189d7",
                        memo: "KNS:1:REG:orphaned-test.secure:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "pending-refund-test.safe",
                        op: "REG",
                        confirmations: 80,
                        status: 7,
                        tx_id: "80ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189d8",
                        memo: "KNS:1:REG:pending-refund-test.safe:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "refunded-test.krgn",
                        op: "REG",
                        confirmations: 120,
                        status: 8,
                        tx_id: "90ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189d9",
                        memo: "KNS:1:REG:refunded-test.krgn:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "extra-item-1.secure",
                        op: "REG",
                        confirmations: 5,
                        status: 5,
                        tx_id: "a0ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189da",
                        memo: "KNS:1:REG:extra-item-1.secure:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    },
                    {
                        domain_name: "extra-item-2.private",
                        op: "REG",
                        confirmations: 5,
                        status: 5,
                        tx_id: "b0ba5332d8fb82d0ffb79355bd8859b724757252fc3b1831ee92f57e9be189db",
                        memo: "KNS:1:REG:extra-item-2.private:ks1mocksourceaddress1234567890abcdefghijklmnopqrstuvwxyz1234567:3757ee1a8b3f10353ca6edd47b66920392b02e323dca3f3edddb5de142079a53:1780469215786:cfec7a589378ae4b767b962271170730d77f2fc5007e30e15d7fd90bec1f10a323ddc403d84a6d1168894ea8d4f39420bba2ec70c0c2a082cf2da5f9ab892004"
                    }
                ].map((item, i) => ({
                    block_id: 5200000 - i * 1440,
                    // One payment stored before times were kept, whose time couldn't be filled in
                    time: i === 4 ? null : 1762150000 - i * 86400,
                    amount: item.op === 'REG' ? 1500000000 : 400000000,
                    price: 0,
                    ...item
                }));

                const start = (page - 1) * count;
                const paginatedTx = allIncomingTx.slice(start, start + count);

                return new Response(JSON.stringify({
                    response: {
                        count: allIncomingTx.length,
                        tx: paginatedTx
                    }
                }), { status: 200, headers: { 'Content-Type': 'application/json' } });
            } else if (type === 'ref') {
                const allRefundTx = [];
                for (let i = 1; i <= 22; i++) {
                    const status = i % 6; // every TX_REFUND_* status, 0..5
                    // Satoshi, as the registrar serves it
                    let amount = i * 100000000;
                    if (i === 1) {
                        amount = 1334360000;
                    } else if (i === 2) {
                        amount = 512000000;
                    }

                    allRefundTx.push({
                        date: 1717838400 - (i * 86400),
                        amount: amount,
                        fee: 5,
                        address: `ks1mockwithdrawaladdress${i}abcdefghijklmnopqrstuvwxyz0123456789`,
                        tx_id: `e95b49dd7ce4830b2fbc696b3e2b0538d55ba22efd622674b0e4af74586e32b${i.toString(16)}`,
                        status: status
                    });
                }

                const start = (page - 1) * count;
                const paginatedTx = allRefundTx.slice(start, start + count);

                return new Response(JSON.stringify({
                    response: {
                        count: allRefundTx.length,
                        tx: paginatedTx
                    }
                }), { status: 200, headers: { 'Content-Type': 'application/json' } });
            }
        }

        // A registrar request the test data has no answer for stays here as well
        if (url.startsWith(apiBase)) {
            return new Response(JSON.stringify({ error: 'Not in the test data' }),
                { status: 404, headers: { 'Content-Type': 'application/json' } });
        }

        return originalFetch.apply(this, arguments);
    };
}
