kr=function(){var e={components:{App:Ce,authorizationPopup:Ae,authorizeBtn:Oe,AuthorizeBtnContainer:ke,authorizeOperationBtn:je,auths:Te,AuthItem:Ie,authError:Pe,oauth2:Ye,apiKeyAuth:Ne,basicAuth:Me,clear:Ge,liveResponse:Qe,InitializedInput:Rn,info:Un,InfoContainer:qn,JumpToPath:zn,onlineValidatorBadge:et.a,operations:rt,operation:lt,OperationSummary:ht,OperationSummaryMethod:dt,OperationSummaryPath:mt,highlightCode:At,responses:Ot,response:Rt,ResponseExtension:Dt,responseBody:Vt,parameters:Kt,parameterRow:Qt,execute:on,headers:an,errors:sn,contentType:pn,overview:Pn,footer:Vn,FilterContainer:Wn,ParamBody:$n,curl:Kn,schemes:Yn,SchemesContainer:Gn,modelExample:Xn,ModelWrapper:Qn,ModelCollapse:Zn,Model:er.a,Models:tr,EnumModel:nr,ObjectModel:or,ArrayModel:ar,PrimitiveModel:sr,Property:ur,TryItOutButton:cr,Markdown:dr.a,BaseLayout:mr,VersionPragmaFilter:lr,VersionStamp:pr,OperationExt:yt,OperationExtRow:bt,ParameterExt:Yt,ParameterIncludeEmpty:Zt,OperationTag:ct,OperationContainer:Se,DeepLink:fr,InfoUrl:Fn,InfoBasePath:Dn,SvgAssets:hr,Example:Re,ExamplesSelect:Be,ExamplesSelectValueRetainer:Ue}},t={components:r},n={components:o};return[pe.default,ce.default,ie.default,re.default,ne.default,ee.default,te.default,oe.default,e,t,se.default,n,ue.default,le.default,fe.default,he.default,de.default,ae.default]},jr=n(322);function Tr(){return[kr,jr.default]}var Ir=n(343);var Pr=!0,Nr="gfdef4ea",Mr="3.52.1",Rr="Fri, 10 Sep 2021 12:03:52 GMT";function Dr(e){var t;H.a.versions=H.a.versions||{},H.a.versions.swaggerUi={version:Mr,gitRevision:Nr,gitDirty:Pr,buildTimestamp:Rr};var n={dom_id:null,domNode:null,spec:{},url:"",urls:null,layout:"BaseLayout",docExpansion:"list",maxDisplayedTags:null,filter:null,validatorUrl:"https://validator.swagger.io/validator",oauth2RedirectUrl:u()(t="".concat(window.location.protocol,"//")).call(t,window.location.host,"/oauth2-redirect.html"),persistAuthorization:!1,configs:{},custom:{},displayOperationId:!1,displayRequestDuration:!1,deepLinking:!1,tryItOutEnabled:!1,requestInterceptor:function(e){return e},responseInterceptor:function(e){return e},showMutatedRequest:!0,defaultModelRendering:"example",defaultModelExpandDepth:1,defaultModelsExpandDepth:1,showExtensions:!1,showCommonExtensions:!1,withCredentials:void 0,requestSnippetsEnabled:!1,requestSnippets:{generators:{curl_bash:{title:"cURL (bash)",syntax:"bash"},curl_powershell:{title:"cURL (PowerShell)",syntax:"powershell"},curl_cmd:{title:"cURL (CMD)",syntax:"bash"}},defaultExpanded:!0,languagesMask:null},supportedSubmitMethods:["get","put","post","delete","options","head","patch","trace"],presets:[Tr],plugins:[],pluginsOptions:{pluginLoadType:"legacy"},initialState:{},fn:{},components:{},syntaxHighlight:{activated:!0,theme:"agate"}},r=Object($.C)(),o=e.domNode;delete e.domNode;var a=v()({},n,e,r),s={system:{configs:a.configs},plugins:a.presets,pluginsOptions:a.pluginsOptions,state:v()({layout:{layout:a.layout,filter:l()(a)},spec:{spec:"",url:a.url},requestSnippets:a.requestSnippets},a.initialState)};if(a.initialState)for(var c in a.initialState)Object.prototype.hasOwnProperty.call(a.initialState,c)&&void 0===a.initialState[c]&&delete s.state[c];var p=new K(s);p.register([a.plugins,function(){return{fn:a.fn,components:a.components,state:a.state}}]);var h=p.getSystem(),m=function(e){var t=h.specSelectors.getLocalConfig?h.specSelectors.getLocalConfig():{},n=v()({},t,a,e||{},r);if(o&&(n.domNode=o),p.setConfigs(n),h.configsActions.loaded(),null!==e&&(!r.url&&"object"===i()(n.spec)&&f()(n.spec).length?(h.specActions.updateUrl(""),h.specActions.updateLoadingStatus("success"),h.specActions.updateSpec(d()(n.spec))):h.specActions.download&&n.url&&!n.urls&&(h.specActions.updateUrl(n.url),h.specActions.download(n.url))),n.domNode)h.render(n.domNode,"App");else if(n.dom_id){var s=document.querySelector(n.dom_id);h.render(s,"App")}else null===n.dom_id||null===n.domNode||console.error("Skipped rendering: no `dom_id` or `domNode` was specified");return h},g=r.config||a.configUrl;return g&&h.specActions&&h.specActions.getConfigByUrl?(h.specActions.getConfigByUrl({url:g,loadRemoteConfig:!0,requestInterceptor:a.requestInterceptor,responseInterceptor:a.responseInterceptor},m),h):m()}Dr.presets={apis:Tr},Dr.plugins=Ir.default;t.default=Dr}]).default}));
