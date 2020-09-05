" Vim syntax file
" Language: Cobalt Strike Aggressor Scripts
" Maintainer: Geert Smelt
" Latest Revision: 05-09-2020

if exists("b:current_syntax")
    finish
endif

" echom "Loading aggressor script syntax highlighting."

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" Define default language elements
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" Strings
syntax region doubleString   start=/"/  skip=/\\"/  end=/"/
syntax region singleString   start=/'/  skip=/\\'/  end=/'/
highlight link doubleString String
highlight link singleString String

" Numbers
syntax match integer "\v[[:digit:]]+"                   " Example: 123
syntax match long "\v[[:digit:]]+L"                     " Example: 12L
syntax match float "\v[[:digit:]]+\.[[:digit:]]+"       " Example: 1.234
syntax match hex "\v0[xX][a-zA-Z0-9]{1,2}"              " Example: 0xFF
highlight link integer Number
highlight link long Number
highlight link float Float
highlight link hex Number

" Arrays
" Example: @(xxx, xxx, xxx,)
syntax region array start=/\v\@\(/ end=/)/ contains=integer,long,float,hex,doubleString,singleString,namedVariables,functionArguments
highlight link array Type

" Hashes
" Example: %(key => 'val', key => 'val')
" TODO: Match the same way arrays are being matched
syntax region hash start=/\v\%/ end=/)/ contains=integer,long,float,hex,doubleString,singleString,namedVariables,functionArguments,operators
highlight link hash Type

" Comments
" Example: # This is a comment
syntax match comment "\v#.*$"
highlight link comment Comment

" Regular variables
" Example: $variable
syntax match namedVariables "\v\$[[:alpha:]_]+" containedin=doubleString,singleString
highlight link namedVariables Identifier

" Function arguments
" Example: $1
syntax match functionArguments "\v\$[[:digit:]]+" containedin=doubleString,singleString
highlight link functionArguments Identifier

" Array variables
" Example: @variable
syntax match arrayVariable "\v\@[A-Za-z0-9_]+" containedin=doubleString,singleString
highlight link arrayVariable Identifier

" Hash variables
" Example: %variable
syntax match hashVariable "\v\%[[:alpha:]]+" containedin=doubleString,singleString
highlight link hashVariable Identifier
" TODO: also denote keywords in a hash as variables
" Example: %unitconversion = %(seconds => 1000, minutes => 60000, hours => 3600000, days => 86400000, weeks => 604800000);

" TODOs
syntax keyword todos TODO XXX FIXME NOTE
highlight link todos Todo

" Keywords
"syntax keyword basicKeywords bind popup item menu set sub inline return yield command on
"syntax keyword basicKeywords bind popup item menu set sub inline return yield command on
syntax keyword Imports import
syntax keyword FunctionMethods alias sub command popup item set new
"syntax keyword conditionalKeywords if iff else return
"syntax keyword miscKeywords pop push popl pushl setf lambda this invoke ohash setMissPolicy callcc
syntax keyword Keywords if else while for return foreach break
syntax keyword Keywords inline
syntax keyword Exceptions try catch throw
"highlight link basicKeywords Statement
"highlight link repeatKeywords Repeat
"highlight link conditionalKeywords Conditional
"highlight link miscKeywords Function
highlight link Imports Function
highlight link FunctionMethods Function
highlight link Keywords Conditional
highlight link Exceptions Exception

" Cobalt Strike Reporting Functions
syntax keyword Reporting agApplications agC2info agCredentials agServices agSessions agTargets agTokens attack_describe attack_detect attack_mitigate attack_name attack_tactics attack_url bookmark br describe h1 h2 h3 h4 kvtable landscape layout list_unordered nobreak output p p_formatted table ts
highlight link Reporting Function

" Cobalt Strike Support Functions
syntax keyword SupportFunctions action addTab addVisualization add_to_clipboard alias alias_clear applications archives

" Deprecated
" https://www.cobaltstrike.com/aggressor-script/migrate.html
syntax keyword Deprecated artifact artifact_stageless drow_listener_smb drow_proxyserver listener_create powershell powershell_encode_oneliner powershell_encode_stager shellcode
highlight link Deprecated Error

syntax match SupportFunctions "\v(\&)?artifact_(general|payload|sign|stager)"

syntax match SupportFunctions "\v(\&)?b(arch|argue_add|argue_list|argue_remove|ase64_decode|ase64_encode|blockdlls|browser|browserpivot|browserpivot_stop|bypassuac|cancel|cd|checkin|clear|connect|covertvpn|cp|data|dcsync|desktop|dllinject|dllload|dllspawn|download|drives|elevate|elevate_command|error|execute|execute_assembly|exit|getprivs|getsystem|getuid|hashdump|info|inject|injectsh|input|ipconfig|jobkill|jobs|jump|kerberos_ccache_use|kerberos_ticket_purge|kerberos_ticket_use|keylogger|kill|link|logonpasswords|loginuser|log2|log|ls|mimikatz|mkdir|mode|mv|net|note|passthehash|pause|portscan|powerpick|powershell|powershell_import|powershell_import_clear|ppid|ps|psexec|psexec_command|psexec_psh|psinject|pwd|reg_query|reg_queryv|remote_exec|rev2self|rm|rportfwd|rportfwd_stop|run|runas|runasadmin|runu|screenshot|setenv|shell|shinject|shspawn|sleep|socks|socks_stop|spawnas|spawnto|spawnu|spawn|ssh_key|ssh|stage|steal_token|sudo|task|timestomp|unlink|upload|upload_raw|wdigest|winrm|wmi)"

syntax match BeaconFunctions "\v(\&)?beacon_(command_describe|command_detail|command_register|commands|data|elevator_describe|elevator_register|elevators|execute_job|exploit_describe|exploit_register|exploits|host_imported_script|host_script|ids|info|link|remote_exec_method_describe|remote_exec_method_register|remote_exec_methods|remote_exploit_arch|remote_exploit_describe|remote_exploit_register|remote_exploits|remove|stage_pipe|stage_tcp)"

syntax match SupportFunctions "\v\b(call|closeClient|colorPanel|credential_add|credentials|data_keys|data_query|dbutton_action|dbutton_help|dialog_description|dialog_show|dialog|dispatch_event|downloads|drow_beacon|drow_checkbox|drow_combobox|drow_exploits|drow_file|drow_interface|drow_krbtgt|drow_listener|drow_listener_stage|drow_mailserver|drow_site|drow_text|drow_text_big|dstamp|elog|encode|fireAlias|fireEvent|format_size|getAggressorClient|gunzip|gzip|highlight|host_delete|host_info|host_update|hosts|insert_component|insert_menu|iprange|keystrokes|licenseKey|listener_create_ext|listener_delete|listener_describe|listener_info|listener_pivot_create|listener_restart|listeners|listeners_local|listeners_stageless|localip|menubar|mynick|nextTab|payload|pgraph|pivots|popup_clear|powershell_command|powershell_compress|pref_get|pref_get_list|pref_set|pref_set_list|previousTab|privmsg|prompt_confirm|prompt_directory_open|prompt_file_open|prompt_file_save|prompt_text|range|removeTab|resetData|say|sbrowser|screenshots|script_resource|separator|services|showVisualization|show_error|show_message|site_host|site_kill|sites|ssh_command_describe|ssh_command_detail|ssh_command_register|ssh_commands|stager|stager_bind_pipe|stager_bind_tcp|str_chunk|str_decode|str_encode|str_xor|sync_download|targets|tbrowser|tokenToEmail|transform|transform_vbs|tstamp|url_open|users|vpn_interface_info|vpn_interfaces|vpn_tap_create|vpn_tap_delete)\b"

" TODO: allow nested use of these functions

syntax match Windows "\v(\&)?open(AboutDialog|ApplicationManager|AutoRunDialog|BeaconBrowser|BeaconConsole|BrowserPivotSetup|BypassUACDialog|CloneSiteDialog|ConnectDialog|CovertVPNSetup|CredentialManager|DownloadBrowser|ElevateDialog|EventLog|FileBrowser|GoldenTicketDialog|HTMLApplicationDialog|HostFileDialog|InterfaceManager|JavaSignedAppletDialog|JavaSmartAppletDialog|JumpDialog|KeystrokeBrowser|ListenerManager|MakeTokenDialog|OfficeMacro|OneLinerDialog|OrActivate|PayloadGeneratorDialog|PayloadHelper|PivotListenerSetup|PortScanner|PortScannerLocal|PowerShellWebDialog|PreferencesDialog|ProcessBrowser|SOCKSBrowser|SOCKSSetup|ScreenshotBrowser|ScriptConsole|ScriptManager|ScriptedWebDialog|ServiceBrowser|SiteManager|SpawnAsDialog|SpearPhishDialog|SystemInformationDialog|SystemProfilerDialog|TargetBrowser|WebLog|WindowsDropperDialog|WindowsExecutableDialog|WindowsExecutableStage)"

syntax keyword SupportFunctions add addAll cast clear concat copy filter flatten map pop push putAll reduce remove removeAll removeAt retainAll reverse search shift size sort sorta sortd sortn splice sublist sum

syntax keyword SupportFunctions formatDate parseDate ticks

syntax keyword SupportFunctions chdir createNewFile cwd deleteFile getFileName getFileParent getFileProper lastModified listRoots lof ls mkdir rename setLastModified setReadOnly

syntax keyword SupportFunctions add clear copy keys ohash ohasha putAll remove setMissPolicy setRemovalPolicy size values

syntax keyword SupportFunctions allocate available bread bwrite closef connect exec fork getConsole listen mark openf print printAll printEOF println readAll readAsObject readb readc readln readObject reset setEncoding sizeof skip wait writeAsObject writeb writeObject

syntax keyword SupportFunctions abs acos asin atan atan2 ceil checksum cos degrees digest double exp floor formatNumber int log long not parseNumber radians rand round sin sqrt srand tan uint

syntax keyword SupportFunctions asc byteAt cast chr charAt find indexOf join lc left lindexOf matched matches mid pack replace replaceAt right split strlen strrep substr tr uc unpack

syntax keyword SupportFunctions acquire casti checkError compile_closure copy debug eval exit expr function getStackTrace global iff include inline invoke lambda let local newInstance popl profile pushl release scalar semaphore setf setField sleep systemProperties taint this typeOf untaint use warn watch

" Cobalt Strike GUI elements
"syntax keyword guiComponents openBeaconBrowser openInterfaceManager openConnectDialog openScriptManager openSOCKSBrowser openScreenshotBrowser openScriptConsole openListenerManager openHTMLApplicationDialog openHostFileDialog openCredentialManager openTargetBrowser openWebLog openKeystrokeBrowser openEventLog openDownloadBrowser openApplicationManager openPreferencesDialog openSiteManager openReportDialog openWindowsExecutableDialog openWindowsDropperDialog openWindowsExecutableStageDialog openOfficeMacroDialog openPayloadGeneratorDialog openPayloadHelper openAutoRunDialog openCloneSiteDialog openScriptManager openJavaSignedAppletDialog openJavaSmartAppletDialog openSystemProfilerDialog openSystemInformationDialog openScriptedWebDialog openSpearPhishDialog openExportDataDialog openAboutDialog openOrActivate openElevateDialog openGoldenTicketDialog openMakeTokenDialog openOneLinerDialog openBrowserPivotSetup openPortScannerLocal openPortScanner openFileBrowser openProcessBrowser openSOCKSSetup openPivotListenerSetup openJumpDialog openServiceBrowser
"syntax keyword windowFunctions sbrowser tbrowser pgraph
"syntax keyword windowFunctions graph_layout showVisualization addVisualization colorPanel
"syntax keyword windowFunctions separator menubar
"syntax keyword windowFunctions prompt_confirm prompt_text host_update insert_menu insert_component  url_open
"syntax keyword windowFunctions closeClient resetData
"syntax keyword beaconFunctions beacons brm binput bexecute bdownload bppid ssh_command_detail ssh_commands ssh_command_describe show_message bhashdump berror blogonpasswords bdesktop bnetview bscreenshot bspawn bsleep bexit bps bsteal_token bkeylogger blog bnote getexplorerpid
"syntax keyword beaconFunctions beacon_exploit_describe beacon_exploits beacon_info beacon_command_detail beacon_command_describe beacon_commands beacon_remove beacon_remote_exploits beacon_remote_exec_methods beacon_remote_exec_method_describe beacon_remote_exploit_arch beacon_remote_exploit_describe beacon_elevators beacon_elevator_describe beacon_note
syntax keyword logFunctions dstamp tstamp ticks mynick
syntax keyword miscFunctions debug remove
syntax keyword miscFunctions matched
syntax keyword miscFunctions checkError
syntax keyword miscFunctions format_size
syntax keyword miscFunctions reports
syntax keyword miscFunctions local eval println expr push chr formatNumber values replace strrep split left shift round double int sorta lambda substr join formatDate lc concat typeof
syntax keyword events beacon_initial
syntax match globals "\v[[:upper:]]+_[[:upper:]]+(_[[:upper:]]+)?"

"syntax keyword functions print join string
highlight link SupportFunctions Function
highlight link windowFunctions Function
highlight link miscFunctions Function
highlight link BeaconFunctions Function
highlight link logFunctions Function
highlight link events Identifier
highlight link globals Structure

syntax match exceptions "\v\^[A-Za-z\.]+"
highlight link exceptions Exception

syntax keyword stringoperations x cmp
"x cmp \\+ - % # \\* \\/ \\^ ==? && =~ <=? >=? (?<!\\.)\\.{2}(?!\\.)
syntax match unarypredicates "\v-is(admin|array|function|hash|letter|number|upper|lower|true|hasmatch|match|active|ssh)"
syntax match unarypredicates "\v-?hasmatch"
syntax keyword stringcomparison eq ne lt gt isin iswm

syntax keyword setoperations in
highlight link setoperations Operator

" Example: checkError($error) isa ^sleep.error.YourCodeSucksException
syntax keyword typecomparison isa
highlight link typecomparison Keyword

" TODO: add the rest of the operators
" x cmp \+ - % # \\* \\/ \\^ ==? && =~ <=? >=? (?<!\\.)\\.{2}(?!\\.)
syntax match numericalcomparison "\v\=\="
syntax match numericalcomparison "\v\!\="
syntax match numericalcomparison "\v\>"
syntax match numericalcomparison "\v\<"
syntax match numericalcomparison "\v\<\="
syntax match numericalcomparison "\v\>\="
syntax match numericalcomparison "\v\<\=\>"

syntax match operators "\v\="
syntax match operators "\v\+"
syntax match operators "\v\."
syntax match operators "\v\.\="
syntax match operators "\v\=\>"
syntax match operators "\v!"
" syntax match operators "\v\.\."    " TODO: Ensure ...... doesn't get matched

" Escape characters
syntax match escapecharacters "\v\\U" containedin=doubleString,singleString contained
syntax match escapecharacters "\v\\u" containedin=doubleString,singleString contained
syntax match escapecharacters "\v\\c." containedin=doubleString,singleString contained
syntax match escapecharacters "\v\\n" containedin=doubleString,singleString contained
syntax match escapecharacters "\v\\o" containedin=doubleString,singleString contained
syntax match escapecharacters "\v\\t" containedin=doubleString,singleString contained
syntax match escapecharacters "\v\\r" containedin=doubleString,singleString contained
syntax match escapecharacters "\v\\x" containedin=doubleString,singleString contained
syntax match escapecharacters "\v\\\\" containedin=doubleString,singleString contained
highlight link escapecharacters Special

" Mnemonics
syntax match mnemonics "\v\&." containedin=doubleString,singleString contained
highlight link mnemonics Special

highlight link unarypredicates Operator
highlight link operators Operator
highlight link stringoperations Operator
highlight link stringcomparison Operator
highlight link numericalcomparison Operator

syntax keyword constants true false
"match": "(?<![^.]\\.|:)\\b(false|true)\\b|(?<![.])\\.{3}(?!\\.)",
highlight link constants Boolean

" Hooks
" https://www.cobaltstrike.com/aggressor-script/hooks.html
syntax keyword hooks APPLET_SHELLCODE_FORMAT EXECUTABLE_ARTIFACT_GENERATOR
                     \ HTMLAPP_EXE HTMLAPP_POWERSHELL POWERSHELL_COMMAND
                     \ POWERSHELL_COMPRESS POWERSHELL_DOWNLOAD_CRADLE
                     \ PSEXEC_SERVICE PYTHON_COMPRESS RESOURCE_GENERATOR
                     \ RESOURCE_GENERATOR_VBS SIGNED_APPLET_MAINCLASS
                     \ SIGNED_APPLET_RESOURCE SMART_APPLET_MAINCLASS
                     \ SMART_APPLET_RESOURCE
highlight link hooks Typedef

" Cobalt Strike Events
" https://www.cobaltstrike.com/aggressor-script/events.html
syntax keyword Events on beacons disconnect ready
syntax match Events "\v(\.)@<!event_(action|beacon_initial|join|newsite|notify|nouser|private|public|quit)"
syntax match BeaconEvents "\v(\.)@<!beacon_(checkin|error|indicator|initial|initial_empty|input|output|output_alt|output_jobs|output_ls|output_ps|tasked)"
syntax match HeartbeatEvents "\v(\.)@<!heartbeat_([[:digit:]]{1,2})(m|s)"
syntax match SendmailEvents "\v(\.)@<!sendmail_(done|post|pre|start)"
syntax match SshEvents "\v(\.)@<!ssh_(checkin|error|indicator|initial|input|output|output_alt|tasked)"
syntax match HitEvents "\v(\.)@<!(keylogger|profiler|web)_hit"
highlight link Events Function
highlight link BeaconEvents Function
highlight link HeartbeatEvents Function
highlight link SendmailEvents Function
highlight link SshEvents Function
highlight link HitEvents Function



let b:current_syntax = "aggressor"
