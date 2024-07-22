const mkErr = msg => new Error(`webpeer-piping: ${msg}`)

export async function webpeerPiping(node){
	
	const debug = true
	let fposturl = ''
	const limitnumber = 10
	let announce = true
	const key = 'UzNRQSX2fIx9fKUsb5lDAWcypVRUiC40DBhvBCdQhpIPA0zreJsm3DYwPe4vVL0J'
	
	let servers = [
		'https://ppng.io/',
		'https://piping-47q675ro2guv.runkit.sh/'
	]
	
	const path = 'webpeerpiping'
	
	if(arguments[0] === undefined){
		throw mkErr('no input')
	}
	
	let api = []
	for(const server of servers){
		for(let i=0;i<5;i++){
			const url = server+path+i
			api.push(url)
		}
	}

	async function fresult(response){
		const result = await response.text();
		const data = await aesGcmDecrypt(result,key)
		const json = JSON.parse(data)
		const id = json.address[0].split('/').pop()
		//console.log('peer found',id)
		
		for(const addr of json.address){
			node.dial(addr)
		}
		
	}
	
	async function fresultcontinue(index,number){
		const newindex = index+1
		if(servers[newindex]){
			fget(newindex,number)
		}else{
			const newnumber = number+1
			if(newnumber < limitnumber){
				fget(0,newnumber)
			}else{
				fget(0,0)
			}
		}
	}
	
	async function fget(index,number){
		if(!servers[index])return
		const url = servers[index]+path+number
		if(url == fposturl){
			fresultcontinue(index,number)
			return
		}
		try {
			const response = await fetch(url, {
			  signal: AbortSignal.timeout(3000)
			});
			if(response.status != 200){
				fresultcontinue(index,number)
				return
			}else{
				fresult(response)
				return
			}
			
		} catch (error) {
			if(error.message.includes('signal timed out')){
			}else{
				servers.splice(index, 1)
				index--
			}
			fresultcontinue(index,number)
			if(debug)console.debug(error)
		}		
		
	}
	fget(0,0)
	
	async function fpostresult(post,index,number){
		try{
			const response = await post

			if(response.status == 200){
				const teks = await response.text()
				if(teks.includes('Waiting')&&!teks.includes('received')){
					//console.log('ok')
				}
			}

		}catch(error){
			servers.splice(index, 1)
			index--
			if(debug)console.debug(error)
		}
		

		
		const newindex = index+1
		if(servers[newindex]){
			fpost(newindex,number)
		}else{
			const newnumber = number+1
			if(newnumber < limitnumber){
				fpost(0,newnumber)
			}else{
				announce = false
				return
			}
		}
	}
	
	async function fpost(index,number){
		if(!servers[index])return
		const address = node.address
		
		const url = servers[index]+path+number
		fposturl = url
		try{
			const msg = JSON.stringify({address:address})
			const data = await aesGcmEncrypt(msg,key)
			const post = fetch(url,{
				method:'POST',
				body: data
			})
			fpostresult(post,index,number)
		}catch(error){
			if(debug)console.debug(error)
		}
		
	}
	
	const timeaddress = setInterval(()=>{
		let address = node.address
		
		if(address.length>0){
			clearInterval(timeaddress)
			fpost(0,0)
		}
	},2000)
	
	setTimeout(()=>{
		if(servers.length>0 && !announce){
			fpost(0,0)
		}
	},2*60*1000)
	

  /**
   * Encrypts plaintext using AES-GCM with supplied password, for decryption with aesGcmDecrypt().
   *                                                                      (c) Chris Veness MIT Licence
   *
   * @param   {String} plaintext - Plaintext to be encrypted.
   * @param   {String} password - Password to use to encrypt plaintext.
   * @returns {String} Encrypted ciphertext.
   *
   * @example
   *   const ciphertext = await aesGcmEncrypt('my secret text', 'pw');
   *   aesGcmEncrypt('my secret text', 'pw').then(function(ciphertext) { console.log(ciphertext); });
   */
  async function aesGcmEncrypt(plaintext, password) {
      const pwUtf8 = new TextEncoder().encode(password);                                 // encode password as UTF-8
      const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);                      // hash the password

      const iv = crypto.getRandomValues(new Uint8Array(12));                             // get 96-bit random iv

      const alg = { name: 'AES-GCM', iv: iv };                                           // specify algorithm to use

      const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']); // generate key from pw

      const ptUint8 = new TextEncoder().encode(plaintext);                               // encode plaintext as UTF-8
      const ctBuffer = await crypto.subtle.encrypt(alg, key, ptUint8);                   // encrypt plaintext using key
  
      const ctArray = Array.from(new Uint8Array(ctBuffer));                              // ciphertext as byte array
      const ctStr = ctArray.map(byte => String.fromCharCode(byte)).join('');             // ciphertext as string
      const ctBase64 = btoa(ctStr);                                                      // encode ciphertext as base64

      const ivHex = Array.from(iv).map(b => ('00' + b.toString(16)).slice(-2)).join(''); // iv as hex string

      return ivHex+ctBase64;                                                             // return iv+ciphertext
  }


  /**
   * Decrypts ciphertext encrypted with aesGcmEncrypt() using supplied password.
   *                                                                      (c) Chris Veness MIT Licence
   *
   * @param   {String} ciphertext - Ciphertext to be decrypted.
   * @param   {String} password - Password to use to decrypt ciphertext.
   * @returns {String} Decrypted plaintext.
   *
   * @example
   *   const plaintext = await aesGcmDecrypt(ciphertext, 'pw');
   *   aesGcmDecrypt(ciphertext, 'pw').then(function(plaintext) { console.log(plaintext); });
   */
  async function aesGcmDecrypt(ciphertext, password) {
      const pwUtf8 = new TextEncoder().encode(password);                                 // encode password as UTF-8
      const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);                      // hash the password

      const iv = ciphertext.slice(0,24).match(/.{2}/g).map(byte => parseInt(byte, 16));  // get iv from ciphertext

      const alg = { name: 'AES-GCM', iv: new Uint8Array(iv) };                           // specify algorithm to use

      const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt']); // use pw to generate key

      const ctStr = atob(ciphertext.slice(24));                                          // decode base64 ciphertext
      const ctUint8 = new Uint8Array(new ArrayBuffer(ctStr.length));
      for (let i = 0; i < ctStr.length; i++) {
          ctUint8[i] = ctStr.charCodeAt(i);
      }

      const plainBuffer = await crypto.subtle.decrypt(alg, key, ctUint8);                // decrypt ciphertext using key
      const plaintext = new TextDecoder().decode(plainBuffer);                           // decode password from UTF-8

      return plaintext;                                                                  // return the plaintext
  }
}