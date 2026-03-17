/**
 * PII Detection Engine
 * Extracted from pii-anonymizer browser tool — identical logic, zero dependencies.
 * Runs in Node.js with no network calls.
 */

// ─── Name Dictionaries ────────────────────────────────────────────────────────

const FIRST_NAMES = new Set(["aaron","abby","abel","abigail","abraham","adam","adrian","adriana","agnes","aiden","alan","albert","alec","alejandro","alex","alexa","alexander","alexandra","alexis","alfred","ali","alice","alicia","alison","allan","allen","allison","alvin","alyssa","amanda","amber","amelia","amy","ana","andrea","andrew","andy","angela","angelica","angelina","anita","ann","anna","anne","annette","annie","anthony","antonio","april","aria","ariana","ashley","audrey","austin","ava","avery","bailey","barbara","barry","beatrice","becky","ben","benjamin","bernard","beth","betty","beverly","bill","billy","blake","bob","bobby","bonnie","brad","bradley","brandon","brenda","brian","bridget","brittany","brooke","bruce","bryan","caleb","calvin","cameron","camille","carl","carla","carlos","carmen","carol","caroline","carolyn","carrie","casey","catherine","cathy","chad","charles","charlie","charlotte","chase","chelsea","cheryl","chris","christian","christina","christine","christopher","cindy","claire","clara","clark","claude","claudia","cody","cole","colin","colleen","connie","connor","corey","courtney","craig","crystal","cynthia","daisy","dale","dallas","dan","dana","daniel","daniela","danielle","danny","dave","david","dawn","dean","deanna","deborah","debra","denise","dennis","derek","diana","diane","don","donald","donna","doris","dorothy","doug","douglas","drew","dustin","dylan","eddie","edgar","edward","eileen","elaine","eleanor","elena","eli","elijah","elizabeth","ella","ellen","emily","emma","eric","erica","erik","erin","ethan","eva","evan","evelyn","faith","felicia","felix","floyd","frances","frank","franklin","fred","frederick","gabriel","gabriela","gail","garrett","gary","gavin","george","gerald","geraldine","gina","gloria","grace","grant","greg","gregory","hailey","haley","hannah","harold","harry","harvey","hayden","heather","heidi","helen","henry","holly","hope","howard","hunter","ian","irene","isaac","isabella","james","jamie","janet","janice","jared","jason","javier","jay","jayden","jean","jeff","jeffrey","jennifer","jenny","jeremy","jerry","jessica","jill","jim","jimmy","joe","joel","john","johnny","jonathan","jordan","jose","joseph","josh","joshua","joy","joyce","julia","julie","june","justin","karen","kate","katherine","kathleen","kathy","katie","kay","kayla","keith","kelly","kelsey","ken","kenneth","kevin","kim","kimberly","kyle","laura","lauren","laurie","lawrence","leah","lee","lena","leo","leon","leslie","levi","lewis","liam","lillian","lily","linda","lisa","logan","lori","louis","louise","lucas","lucy","luis","luke","lydia","madison","maggie","malcolm","mandy","marc","marcus","margaret","maria","marilyn","mario","mark","martha","martin","mary","mason","matt","matthew","maya","megan","melissa","michael","michelle","miguel","mike","miranda","molly","monica","morgan","nancy","naomi","natalie","natasha","nathan","nicholas","nick","nicole","noah","nora","oliver","olivia","patricia","patrick","paul","paula","peter","phil","philip","phyllis","rachel","ralph","ray","raymond","rebecca","richard","rick","riley","rob","robert","robin","roger","ron","ronald","rosa","rose","ross","roy","ruby","russell","ruth","ryan","samantha","samuel","sandra","sara","sarah","scott","sean","seth","shannon","sharon","shawn","sheila","shelby","shirley","sierra","sophia","sophie","stanley","stephanie","stephen","steve","steven","sue","susan","suzanne","sydney","sylvia","tamara","tammy","tanya","tara","taylor","teresa","thomas","tiffany","tim","timothy","tina","todd","tom","tony","tonya","tracy","travis","trevor","tyler","tyrone","valerie","vanessa","vera","victor","victoria","vincent","virginia","vivian","wade","walter","wanda","warren","wayne","wendy","wesley","william","willie","wilma","wyatt","xavier","yolanda","yvonne","zachary","zoe","rahul","raj","priya","arjun","kofi","ahmed","ali","fatima","hassan","ibrahim","muhammad","omar","yasmin","chen","wei","ming","jian","hong","lin","yan","lei","junho","sehun","jimin","taehyung","yoongi","jungkook","seojin","minji","nina","rafael","elena","rosa","carmen","lucia","diego","pablo","sergio","andres","jorge","carlos","miguel","pedro","raul","rodrigo","santiago","mateo","luca","nico","kai","ravi","sanjay","deepak","suresh","anil","manoj","vikram"]);

const LAST_NAMES = new Set(["smith","johnson","williams","brown","jones","garcia","miller","davis","rodriguez","martinez","hernandez","lopez","gonzalez","wilson","anderson","thomas","taylor","moore","jackson","martin","lee","perez","thompson","white","harris","sanchez","clark","ramirez","lewis","robinson","walker","young","allen","king","wright","scott","torres","nguyen","hill","flores","green","adams","nelson","baker","hall","rivera","campbell","mitchell","carter","roberts","gomez","phillips","evans","turner","diaz","parker","cruz","edwards","collins","reyes","stewart","morris","morales","murphy","cook","rogers","ortiz","morgan","cooper","peterson","bailey","reed","kelly","howard","ramos","kim","cox","ward","richardson","watson","brooks","chavez","wood","james","bennett","gray","mendoza","ruiz","hughes","price","alvarez","castillo","sanders","patel","myers","long","ross","foster","jimenez","powell","jenkins","perry","russell","sullivan","bell","coleman","butler","henderson","barnes","fisher","vasquez","simmons","griffin","marshall","owens","harrison","fernandez","lawson","wells","webb","tucker","freeman","burns","henry","crawford","boyd","mason","kennedy","warren","dixon","burns","gordon","shaw","holmes","rice","robertson","daniels","palmer","mills","nichols","grant","knight","ferguson","stone","hawkins","dunn","perkins","hudson","spencer","gardner","stephens","payne","pierce","berry","owusu","mensah","asante","amoah","boateng","appiah","adjei","osei","acheampong","annan","mahajan","sharma","patel","gupta","singh","mehta","verma","shah","joshi","iyer","nair","reddy","rao","kulkarni","khan","ahmed","ali","hussain","malik","sheikh","siddiqui","chang","liang","liu","wang","zhang","zhao","zheng","zhou","zhu","tanaka","yamamoto","nakamura","suzuki","sato","watanabe","kobayashi","ito","kato","yoshida","kwon","park","choi","cho","yoon","han","lim","jung","kang","moon","seo","shin","ahn","bautista","reyes","santos","dela","garcia","flores","gonzales","hernandez","torres","ramirez","castillo","doe","roe","bloggs","public","sample","test","example","demo","person","user","smith","jones","brown"]);

const SUPPRESS_WORDS = new Set(["the","and","for","that","this","with","from","are","was","were","been","have","has","had","will","would","could","should","may","might","must","shall","can","not","but","nor","yet","also","than","then","when","where","which","while","who","what","how","all","each","every","both","few","more","most","other","some","such","only","same","too","very","just","about","above","after","before","below","between","during","into","through","under","his","her","its","our","your","their","him","she","they","them","here","there","info","data","type","form","file","note","item","list","page","date","time","code","name","text","sent","read","last","info","state","inc","corp","ltd","llc","company","group","bank","error","warn","null","undefined","true","false","check","stock","trade","save","share","hold","sell","buy","link","said","real","time","available","routing","account","card","credit","debit","ssn","social","security","passport","license","licence","driver","email","phone","address","token","session","device","user","password","secret","key","january","february","march","april","july","august","september","october","november","december","monday","tuesday","wednesday","thursday","friday","saturday","sunday","jan","feb","mar","apr","jun","jul","aug","sep","oct","nov","dec","mon","tue","wed","thu","fri","sat","sun","spring","autumn","winter","release","version","build","update","draft","review","mode","behind","feature","improve","throughput","rows","keeps","docs","metric","window","bucket","status","count","slug","appears","sample","remains","invalid","design","example","postcode","fake","change","changes","current","previous","latest","stable"]);

const AMBIGUOUS_NAME_WORDS = new Set(["will","chase","sterling","bill","rose","stone","cole","summer","june","grace","hope","faith","joy","dawn","pearl","iris","violet","ivy","holly","lily","daisy","ruby","amber","crystal","misty","sandy","penny","pat","mark","frank","drew","wade","grant","hunter","mason","carter","parker","reed","brooks","tucker","porter","fisher","bailey","marshall","spencer","page","nelson","lee","long","young","rich","cook","bell","ford","moss","cross","bond","dale","lane","love","may","ray","ash","wolf","fox","hawk","april","august","art","angel","norm","troy","glen","cliff","heath","marsh","brook","lake","miles","chance","skip","jean","bob","max","al","don","gene","guy","ray","dean","earl","duke","baron","king","prince","bishop","judge","major","victor","jack","ben","harry","nick","joe","tim","mac","sue","eve","jay","ted","dan","rob","ken","roy","rex","bud","ed","austin","charlotte","phoenix","dallas","jordan","taylor","morgan","madison","logan","blake","riley","casey","devon","shelby","denver","orlando","dakota","savannah","sierra","brooklyn","chelsea","regina","florence","adelaide","georgia","victoria","carolina","virginia","montana","india","china","asia","america","paris","london","milan","sydney","dublin","berlin","lima","sofia","aurora","olive","ocean","river","field","north","south","east","west","spring","winter","camp","white","black","green","gray","grey","silver","gold","price","love","sweet","bliss","sage","sterling","cash","cannon","arrow","blade"]);

const NAME_CONTEXT_BEFORE = /(?:dear|hey|hi|hello|thanks|thank\s+you|cheers|regards|sincerely|attn|attention|cc|bcc|from|to|signed\s+by|authored\s+by|written\s+by|submitted\s+by|reviewed\s+by|approved\s+by|created\s+by|assigned\s+to|reported\s+by|patient|client|customer|employee|applicant|tenant|borrower|claimant|contact|agent|officer|manager|director|name|full\s+name|first\s+name|last\s+name|surname|account\s+holder|cardholder|payee|payer|sender|recipient|mr|mrs|ms|miss|dr|prof|sir|ship\s+to|beneficiary)\s*[:,]?\s*$|"(?:name|fullName|full_name|firstName|first_name|lastName|last_name|displayName|display_name|beneficiary|recipient|payee|payer|cardholder|account_holder)"\s*:\s*"$/i;

// ─── Luhn Check ───────────────────────────────────────────────────────────────

function luhnCheck(num) {
  const d = num.replace(/\D/g, "");
  if (d.length < 13 || d.length > 19) return false;
  let s = 0, a = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = parseInt(d[i], 10);
    if (a) { n *= 2; if (n > 9) n -= 9; }
    s += n; a = !a;
  }
  return s % 10 === 0;
}

// ─── BIP-39 Seed Phrase Detection ─────────────────────────────────────────────

const BIP39_COMMON = new Set(["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual","adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction"]);

function isSeedPhrase(t) {
  const w = t.toLowerCase().trim().split(/\s+/);
  if (w.length !== 12 && w.length !== 24) return false;
  return w.filter(x => BIP39_COMMON.has(x)).length >= w.length * 0.5;
}

// ─── Patterns ─────────────────────────────────────────────────────────────────

const patterns = [
  { id:"eth_address", label:"Ethereum Address", tier:"Crypto", pattern:/\b0x[a-fA-F0-9]{40}\b/g, placeholder:"CRYPTO_ADDRESS" },
  { id:"btc_bech32", label:"Bitcoin Bech32", tier:"Crypto", pattern:/\bbc1[a-zA-Z0-9]{39,59}\b/gi, placeholder:"CRYPTO_ADDRESS" },
  { id:"btc_legacy", label:"Bitcoin Legacy", tier:"Crypto", pattern:/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, placeholder:"CRYPTO_ADDRESS" },
  { id:"jwt_token", label:"JWT Token", tier:"Crypto", pattern:/\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g, placeholder:"ACCESS_TOKEN" },
  { id:"api_key_secret", label:"API Key / Secret", tier:"Crypto", pattern:/\b(?:sk_live_[a-zA-Z0-9]{20,}|sk_test_[a-zA-Z0-9]{20,}|pk_live_[a-zA-Z0-9]{20,}|pk_test_[a-zA-Z0-9]{20,}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}|glpat-[a-zA-Z0-9\-]{20,}|xox[bpsa]-[a-zA-Z0-9\-]{10,})\b/gi, placeholder:"API_KEY" },
  { id:"credit_card", label:"Credit Card", tier:"Financial", pattern:/\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|35(?:2[89]|[3-8][0-9])|6(?:011|5[0-9]{2}))[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{1,4}\b/g, validate:(m)=>luhnCheck(m), placeholder:"CREDIT_CARD" },
  { id:"iban", label:"IBAN", tier:"Financial", pattern:/\b[A-Za-z]{2}\d{2}[- ]?[A-Za-z0-9]{4}[- ]?(?:[A-Za-z0-9]{4}[- ]?){1,7}[A-Za-z0-9]{1,4}\b/g, placeholder:"BANK_ACCOUNT" },
  { id:"routing_number", label:"Routing Number", tier:"Financial", pattern:/\b(?:routing)[#:\s]*(\d{9})\b/gi, placeholder:"ROUTING_NUMBER", captureGroup:1 },
  { id:"account_number", label:"Account Number", tier:"Financial", pattern:/\b(?:account|acct)[#:\s]*(\d{8,17})\b/gi, placeholder:"BANK_ACCOUNT", captureGroup:1 },
  { id:"uk_sortcode", label:"UK Sort Code", tier:"Financial", pattern:/\b\d{2}[-–]\d{2}[-–]\d{2}\b/g, placeholder:"SORT_CODE" },
  { id:"ssn", label:"SSN (US)", tier:"Identity", pattern:/\b(?!000|666)\d{3}[-–]\d{2}[-–]\d{4}\b/g, placeholder:"SSN" },
  { id:"uk_nino", label:"UK NI Number", tier:"Identity", pattern:/\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi, placeholder:"SSN" },
  { id:"passport", label:"Passport Number", tier:"Identity", pattern:/\b(?:passport)[#:\s]*([A-Z0-9]{6,12})\b/gi, placeholder:"PASSPORT_NUMBER", captureGroup:1 },
  { id:"drivers_license", label:"Driver's License", tier:"Identity", pattern:/\b(?:DL|driver'?s?\s*(?:license|licence))[#:\s]*([A-Z0-9]{5,14})\b/gi, placeholder:"DRIVER_LICENSE", captureGroup:1 },
  { id:"ipv4", label:"IPv4 Address", tier:"Network", pattern:/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, validate:(m)=>!m.startsWith("0."), placeholder:"IP_ADDRESS" },
  { id:"mac_address", label:"MAC Address", tier:"Network", pattern:/\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b/g, placeholder:"MAC_ADDRESS" },
  { id:"email", label:"Email Address", tier:"Contact", pattern:/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, placeholder:"EMAIL" },
  { id:"phone_intl", label:"Phone (International)", tier:"Contact", pattern:/\+[1-9]\d{0,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{1,4}[\s.\-]?\d{1,9}(?=[\s,;:!?)}\]"']|$)/g, validate:(m)=>{const d=m.replace(/\D/g,"");return d.length>=7&&d.length<=15&&!/\n/.test(m);}, placeholder:"PHONE_NUMBER" },
  { id:"phone_contextual", label:"Phone (contextual)", tier:"Contact", pattern:/\b(?:tel|phone|ph|mobile|mob|cell|fax|contact|call|number|no)\s*[:\-#]?\s*(\(?\+?[\d][\d\s.\-()]{6,19}[\d)])/gi, validate:(m)=>{const d=m.replace(/\D/g,"");return d.length>=7&&d.length<=15;}, placeholder:"PHONE_NUMBER", captureGroup:1 },
  { id:"uk_postcode", label:"UK Postcode", tier:"Address", pattern:/\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b/gi, validate:(m)=>{const upper=m.toUpperCase().replace(/\s/g,"");if(/^ZZ|^XX|^QQ|^BF1/.test(upper))return false;if(/^([A-Z])\1\d/.test(upper)&&!/^(EE|LL|NN|SS|WW)/.test(upper))return false;return true;}, placeholder:"ZIP_CODE" },
  { id:"us_zip", label:"US ZIP Code", tier:"Address", pattern:/\b\d{5}(?:-\d{4})?\b/g, validate:(m,t,i)=>{const before=t.slice(Math.max(0,i-30),i);const after=t.slice(i+m.length,i+m.length+40);if(/[":]\s*$/.test(before)&&/[{,]/.test(before))return false;if(/,\s*$/.test(before)){const lineStart=t.lastIndexOf("\n",i-1);const line=t.slice(lineStart+1,i+m.length+20);if(/^\s*\w+,/.test(line))return false;}if(/^\s*[,}]/.test(after)&&/[{"]/.test(before))return false;if(/\bto\s+\d+$/.test(before))return false;if(/^\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Close|Terrace|Ter|Crescent|Cres)\b/i.test(after))return false;const hasStateCtx=/,\s*[A-Z]{2}\s*$/.test(before);const hasZipCtx=/(?:zip|postal|postcode|code)\s*[:\-#]?\s*$/i.test(before);const hasAddrCtx=/(?:address|city|state|mailing|ship|shipping|deliver|mobile|phone|street|avenue|road|drive|lane|court|boulevard)\b/i.test(t.slice(Math.max(0,i-200),i+m.length+100));if(hasStateCtx||hasZipCtx||hasAddrCtx)return true;const sameLineAfter=after.split('\n')[0];if(/^ +[A-Za-z]/.test(sameLineAfter))return false;return true;}, placeholder:"ZIP_CODE" },
  { id:"street_address", label:"Street Address", tier:"Address", pattern:/\b\d+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Close|Terrace|Ter|Crescent|Cres)\b/gi, placeholder:"STREET_ADDRESS" },
  { id:"date_dob", label:"Date of Birth", tier:"Identity", pattern:/\b(?:DOB|date\s+of\s+birth|born|birthday)\s*[:\-]?\s*(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})\b/gi, placeholder:"DATE", captureGroup:1 },
  { id:"date_full", label:"Date", tier:"Contact", pattern:/\b(?:\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}|\d{4}-\d{2}-\d{2})\b/g, validate:(m,t,i)=>{const before=t.slice(Math.max(0,i-40),i);if(/"(?:build|date|created|updated|timestamp|version|window|released?|published)"\s*:\s*"?$/i.test(before))return false;if(/(?:build|version|release|window|slug)[=:]\s*"?$/i.test(before))return false;if(/,\s*$/.test(before)){const lineStart=t.lastIndexOf("\n",i-1);const line=t.slice(lineStart+1,i+m.length+5);if(/^\s*\w+,/.test(line))return false;}return true;}, placeholder:"DATE" },
  { id:"name_title", label:"Name (with title)", tier:"Names", pattern:/\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Dame|Lady|Rev|Capt|Sgt)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z']+){0,3}\b/g, placeholder:"PERSON_NAME" },
  { id:"name_dictionary", label:"Known Name", tier:"Names", pattern:/\b[a-zA-Z]{2,}\b/g, validate:(m,t,i)=>{const lo=m.toLowerCase();if(SUPPRESS_WORDS.has(lo))return false;const after=t.slice(i+m.length,i+m.length+10);if(/^,\s*[A-Z]{2}\b/.test(after))return false;if(AMBIGUOUS_NAME_WORDS.has(lo)){const before=t.slice(Math.max(0,i-60),i);if(NAME_CONTEXT_BEFORE.test(before))return true;const immBefore=t.slice(Math.max(0,i-30),i);const prevWordMatch=immBefore.match(/\b([A-Z][a-z]+)\s+$/);if(prevWordMatch&&FIRST_NAMES.has(prevWordMatch[1].toLowerCase()))return true;return false;}return FIRST_NAMES.has(lo)||LAST_NAMES.has(lo);}, placeholder:"PERSON_NAME" },
  { id:"device_id", label:"Device ID", tier:"System", pattern:/\b(?:DEV|DEVICE|device)[_\-][a-zA-Z0-9_\-]{6,}\b/g, placeholder:"DEVICE_ID" },
  { id:"session_id", label:"Session Token", tier:"System", pattern:/\b(?:SESSION|session|sess|TOKEN|token)[_\-][a-zA-Z0-9_\-]{6,}\b/g, validate:(m)=>{const suffix=m.replace(/^[a-zA-Z]+[_\-]/,"");const parts=suffix.split(/[_\-]/);const COMMON_WORDS=new Set(["summary","report","data","info","log","note","docs","doc","page","item","list","file","test","demo","example","sample","draft","config","key","val","value","result","output","input","temp","tmp","cache","index","name","type","kind","code","tag","set","get","run","job","task","step","stage","node","host","env","mode","flag","beta","alpha","rc","dev","prod","staging"]);if(parts.some(p=>COMMON_WORDS.has(p.toLowerCase())))return false;return true;}, placeholder:"SESSION_TOKEN" },
  { id:"user_id", label:"User ID", tier:"System", pattern:/\b(?:USR|USER|user)[_\-][a-zA-Z0-9_\-]{6,}\b/g, placeholder:"USER_ID" },
  { id:"uuid", label:"UUID", tier:"System", pattern:/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, placeholder:"UUID" },
];

// ─── Context Rules (Rule 3) ────────────────────────────────────────────────────

const CONTEXT_RULES = [
  { keywords:/\b(?:ssn|social\s+security|ss\s*#?)\b/i, digitLen:[9], label:"SSN (contextual)", placeholder:"SSN" },
  { keywords:/\b(?:routing|aba|transit)\b/i, digitLen:[9], label:"Routing Number (contextual)", placeholder:"ROUTING_NUMBER" },
  { keywords:/\b(?:account|acct|a\/c)\b/i, digitLen:[8,9,10,11,12,13,14,15,16,17], label:"Account Number (contextual)", placeholder:"BANK_ACCOUNT" },
  { keywords:/\b(?:card|visa|mastercard|amex|credit|debit)\b/i, digitLen:[15,16], label:"Card Number (contextual)", placeholder:"CREDIT_CARD", validate:(m)=>luhnCheck(m) },
  { keywords:/\b(?:passport)\b/i, digitLen:[6,7,8,9], label:"Passport (contextual)", placeholder:"PASSPORT_NUMBER" },
  { keywords:/\b(?:license|licence|DL)\b/i, digitLen:[5,6,7,8,9,10,11,12,13,14], label:"License (contextual)", placeholder:"DRIVER_LICENSE" },
  { keywords:/\b(?:member|employee|staff|patient|client|customer)\s*(?:#|no|num|number)?\b/i, digitLen:[4,5,6,7,8,9,10,11,12], label:"ID Number (contextual)", placeholder:"USER_ID" },
  { keywords:/\b(?:policy|claim|case|ref|reference|invoice|order)\s*(?:#|no|num|number)?\b/i, digitLen:[4,5,6,7,8,9,10,11,12,13,14,15], label:"Reference Number (contextual)", placeholder:"USER_ID" },
];

function contextClassify(text, matches) {
  const numRe = /\b\d[\d\s\-]{3,20}\d\b/g;
  let nm;
  while ((nm = numRe.exec(text)) !== null) {
    const nStart = nm.index, nEnd = nStart + nm[0].length;
    if (matches.some(m => nStart >= m.start && nStart < m.end)) continue;
    const digits = nm[0].replace(/\D/g, "");
    const ctxBefore = text.slice(Math.max(0, nStart - 80), nStart);
    const ctxAfter = text.slice(nEnd, Math.min(text.length, nEnd + 40));
    const ctx = ctxBefore + " " + ctxAfter;
    for (const rule of CONTEXT_RULES) {
      if (!rule.keywords.test(ctx)) continue;
      if (rule.digitLen && !rule.digitLen.includes(digits.length)) continue;
      if (rule.validate && !rule.validate(nm[0])) continue;
      matches.push({ start: nStart, end: nEnd, label: rule.label, placeholder: rule.placeholder });
      break;
    }
  }
}

// ─── Entity Registry (Rule 6 — consistency) ──────────────────────────────────

function createRegistry() { return {}; }

function normalizeValue(raw, type) {
  if (type === "PERSON_NAME" || type === "EMAIL") return raw.toLowerCase().trim();
  return raw.replace(/[\s\-]+/g, "").toLowerCase().trim();
}

function getPlaceholder(registry, raw, type) {
  if (!registry[type]) registry[type] = { valueMap: new Map(), counter: 0 };
  const reg = registry[type];
  const key = normalizeValue(raw, type);
  if (reg.valueMap.has(key)) return `[${type}_${reg.valueMap.get(key)}]`;
  reg.counter++;
  reg.valueMap.set(key, reg.counter);
  return `[${type}_${reg.counter}]`;
}

function simplifyPlaceholder(registry, tag) {
  const m = tag.match(/^\[([A-Z_]+)_(\d+)\]$/);
  if (!m) return tag;
  const type = m[1];
  const reg = registry[type];
  if (reg && reg.counter === 1) return `[${type}]`;
  return tag;
}

// ─── Custom Dictionaries (user-provided) ─────────────────────────────────────

let customNames = new Set();
let customPatterns = [];

export function addCustomNames(names) {
  for (const n of names) customNames.add(n.toLowerCase().trim());
}

export function addCustomPatterns(userPatterns) {
  for (const p of userPatterns) {
    customPatterns.push({
      id: `custom_${p.label || p.placeholder || "pattern"}`,
      label: p.label || "Custom Pattern",
      pattern: new RegExp(p.regex, p.flags || "gi"),
      placeholder: p.placeholder || "CUSTOM_PII",
      validate: null,
    });
  }
}

export function clearCustomDictionaries() {
  customNames = new Set();
  customPatterns = [];
}

export function getCustomStats() {
  return {
    customNames: customNames.size,
    customPatterns: customPatterns.length,
  };
}

// ─── Load from config file on startup ────────────────────────────────────────

import { readFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export function loadConfig(configPath) {
  const fullPath = resolve(configPath);
  if (!existsSync(fullPath)) return { loaded: false, error: `File not found: ${fullPath}` };

  try {
    const raw = readFileSync(fullPath, "utf-8");
    const config = JSON.parse(raw);
    let namesLoaded = 0;
    let patternsLoaded = 0;
    let filesLoaded = 0;

    // Load inline names array
    if (Array.isArray(config.names)) {
      addCustomNames(config.names);
      namesLoaded += config.names.length;
    }

    // Load names from external files (one name per line, or CSV)
    if (Array.isArray(config.nameFiles)) {
      for (const file of config.nameFiles) {
        const filePath = resolve(dirname(fullPath), file);
        if (!existsSync(filePath)) continue;
        const content = readFileSync(filePath, "utf-8");
        const names = content.split(/[\n,]/).map(n => n.trim()).filter(n => n && n.length >= 2);
        addCustomNames(names);
        namesLoaded += names.length;
        filesLoaded++;
      }
    }

    // Load inline patterns
    if (Array.isArray(config.patterns)) {
      addCustomPatterns(config.patterns);
      patternsLoaded += config.patterns.length;
    }

    return { loaded: true, namesLoaded, patternsLoaded, filesLoaded };
  } catch (e) {
    return { loaded: false, error: e.message };
  }
}

// Auto-load config if pii-config.json exists next to engine
const defaultConfig = resolve(__dirname, "pii-config.json");
if (existsSync(defaultConfig)) {
  const result = loadConfig(defaultConfig);
  if (result.loaded) {
    console.error(`[pii-anonymizer] Loaded config: ${result.namesLoaded} names, ${result.patternsLoaded} patterns from pii-config.json`);
  }
}

// ─── Main Anonymize Function ──────────────────────────────────────────────────

export function anonymize(text, enabledPatternIds = null) {
  if (!text || !text.trim()) return { anonymized: "", entityMap: {}, count: 0 };

  const registry = createRegistry();
  const active = enabledPatternIds
    ? patterns.filter(p => enabledPatternIds.includes(p.id))
    : patterns;

  const allMatches = [];

  // Seed phrase detection
  const lines = text.split("\n");
  for (const line of lines) {
    if (isSeedPhrase(line)) {
      const idx = text.indexOf(line);
      allMatches.push({ start: idx, end: idx + line.length, label: "BIP-39 Seed Phrase", placeholder: "ACCESS_TOKEN" });
    }
  }

  // Custom name matching (supports words with underscores, hyphens, dots)
  if (customNames.size > 0) {
    const lcText = text.toLowerCase();
    for (const name of customNames) {
      let pos = 0;
      while ((pos = lcText.indexOf(name, pos)) !== -1) {
        const before = pos > 0 ? text[pos - 1] : " ";
        const after = pos + name.length < text.length ? text[pos + name.length] : " ";
        const isBoundaryBefore = /[\s,;:!?()[\]{}"'<>\/|\\^~`@#$%&*+=\n\r\t]/.test(before) || pos === 0;
        const isBoundaryAfter = /[\s,;:!?()[\]{}"'<>\/|\\^~`@#$%&*+=\n\r\t]/.test(after) || pos + name.length === text.length;
        if (isBoundaryBefore && isBoundaryAfter) {
          allMatches.push({ start: pos, end: pos + name.length, label: "Custom Name", placeholder: "PERSON_NAME" });
        }
        pos += name.length;
      }
    }
  }

  // Custom pattern matching
  for (const cp of customPatterns) {
    const regex = new RegExp(cp.pattern.source, cp.pattern.flags);
    let cm;
    while ((cm = regex.exec(text)) !== null) {
      allMatches.push({ start: cm.index, end: cm.index + cm[0].length, label: cp.label, placeholder: cp.placeholder });
    }
  }

  // Pattern matching
  for (const p of active) {
    const regex = new RegExp(p.pattern.source, p.pattern.flags);
    let m;
    while ((m = regex.exec(text)) !== null) {
      if (p.validate && !p.validate(m[0], text, m.index)) continue;
      if (p.captureGroup && m[p.captureGroup] !== undefined) {
        // Use capture group — only redact the value, not the keyword
        const groupVal = m[p.captureGroup];
        const groupStart = m.index + m[0].indexOf(groupVal);
        allMatches.push({ start: groupStart, end: groupStart + groupVal.length, label: p.label, placeholder: p.placeholder || "ACCESS_TOKEN" });
      } else {
        allMatches.push({ start: m.index, end: m.index + m[0].length, label: p.label, placeholder: p.placeholder || "ACCESS_TOKEN" });
      }
    }
  }

  // Context-aware classification (Rule 3)
  contextClassify(text, allMatches);

  // Sort and resolve overlaps — score-based: prefer narrower, more specific matches
  function matchScore(m) {
    let score = 0;
    // Prefer narrower matches (value-only over label+value)
    const len = m.end - m.start;
    score -= len * 0.1;
    // Prefer specific pattern types over contextual/generic
    const SPECIFIC = new Set(["CREDIT_CARD","SSN","EMAIL","IP_ADDRESS","UUID","MAC_ADDRESS","CRYPTO_ADDRESS","API_KEY","ACCESS_TOKEN","PASSPORT_NUMBER","DRIVER_LICENSE","SORT_CODE"]);
    if (SPECIFIC.has(m.placeholder)) score += 100;
    // Prefer validated matches
    if (m.validated) score += 50;
    return score;
  }

  allMatches.sort((a, b) => a.start - b.start || matchScore(b) - matchScore(a) || (a.end - a.start) - (b.end - b.start));
  const resolved = [];
  let lastEnd = 0;
  for (const match of allMatches) {
    if (match.start >= lastEnd) {
      resolved.push(match);
      lastEnd = match.end;
    }
  }

  // Assign placeholders (Rule 6 — consistency)
  for (const match of resolved) {
    match.tag = getPlaceholder(registry, text.slice(match.start, match.end), match.placeholder);
  }
  for (const match of resolved) {
    match.tag = simplifyPlaceholder(registry, match.tag);
  }

  // Build output + entity map
  let output = "";
  let cursor = 0;
  const entityMap = {}; // placeholder → original value

  for (const match of resolved) {
    output += text.slice(cursor, match.start) + match.tag;
    entityMap[match.tag] = text.slice(match.start, match.end);
    cursor = match.end;
  }
  output += text.slice(cursor);

  return {
    anonymized: output,
    entityMap,
    count: resolved.length,
    detectedTypes: [...new Set(resolved.map(r => r.placeholder))],
  };
}

export function deanonymize(anonymizedText, entityMap) {
  let result = anonymizedText;
  // Sort by length descending to avoid partial replacements
  const entries = Object.entries(entityMap).sort((a, b) => b[0].length - a[0].length);
  for (const [placeholder, original] of entries) {
    result = result.split(placeholder).join(original);
  }
  return result;
}
