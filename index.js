let { Cc, Ci, Cu, Cr } = require('chrome');

let gDevTools;
try
{
	({gDevTools} = Cu.import("resource://devtools/client/framework/gDevTools.jsm", {}));
}
catch (e)
{
	({gDevTools} = Cu.import("resource:///modules/devtools/gDevTools.jsm", {}));
}
//let {Services} = Cu.import("resource://gre/modules/Services.jsm", {});





function startup(params, reason)
{
	addonData = params;
    console.log("STARTUP...");
}


function Panel(window, toolbox) {}
Panel.prototype = {
	destroy: function() {},
	onNewScript: function(message) {},
	onScriptExecuted: function(message) {},
	onNavigate: function() {}
};







let domi = {
	id: "domi",
	url: "chrome://domi/content/panel.xul",
	label: 'domi.label',
	tooltip: 'domi.tooltip',
//	icon: "chrome://domi/domi.svg",
	inMenu: true,
	menuLabel: 'Domi.menulabel',
	invertIconForLightTheme: true,
	isTargetSupported: target => target.isLocalTab,
	build: (window, toolbox) => {
		return new Panel(window, toolbox).ready;
	}
};

gDevTools.registerTool(domi);



