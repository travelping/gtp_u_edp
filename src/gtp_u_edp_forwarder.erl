%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp_forwarder).

-behaviour(gen_server).

%% API
-export([start_link/3, create_session/3]).
-export([handle_msg/6]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("gtplib/include/gtp_packet.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
-include("include/gtp_u_edp.hrl").

-define(SERVER, ?MODULE).
-define('Tunnel Endpoint Identifier Data I',	{tunnel_endpoint_identifier_data_i, 0}).
-define('GTP-U Peer Address',			{gsn_address, 0}).

-record(pdr, {
	  name,
	  pid			:: 'undefined' | pid(),
	  src_if		:: 'access' | 'core',
	  tei,
	  far_id,
	  urr_id = []
	 }).
-record(far, {
	  name,
	  pid			:: 'undefined' | pid(),
	  dst_if		:: 'access' | 'core',
	  action = drop		:: 'forward' | 'buffer' | 'drop',
	  ip,
	  tei
	 }).
-record(counter, {
	  dl = {0, 0},
	  ul = {0, 0},
	  total = {0, 0},
	  dropped_dl = {0, 0},
	  dropped_ul = {0, 0}
	 }).

-record(state, {
	  owner,
	  name,
	  seid,
	  pdr = #{},
	  far = #{},
	  urr = #{}
	 }).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Name, Owner, SER) ->
    gen_server:start_link(?MODULE, [Name, Owner, SER], []).

create_session(Name, Owner, SER) ->
    gtp_u_edp_handler_sup:create_session(Name, Owner, SER).

handle_msg(Name, Socket, Req, IP, Port, #gtp{type = g_pdu, tei = TEI, seq_no = _SeqNo} = Msg)
  when is_integer(TEI), TEI /= 0 ->
    lager:debug("EDP: ~p", [{Name, TEI}]),
    case gtp_u_edp:lookup({Name, TEI}) of
	{Handler, PdrId} when is_pid(Handler) ->
	    gen_server:cast(Handler, {handle_msg, PdrId, Req, Msg});
	_ ->
	    gtp_u_edp_port:send_error_indication(Socket, IP, TEI, [{udp_port, Port}]),
	    gtp_u_edp_metrics:measure_request_error(Req, context_not_found),
	    ok
    end;
handle_msg(Name, _Socket, Req, IP, Port,
	   #gtp{type = error_indication,
		ie = #{?'Tunnel Endpoint Identifier Data I' :=
			   #tunnel_endpoint_identifier_data_i{tei = TEI}}} = Msg) ->
    lager:notice("error_indication from ~p:~w, TEI: ~w", [IP, Port, TEI]),
    lager:debug("EDP: ~p", [{Name, {remote, IP, TEI}}]),
    case gtp_u_edp:lookup({Name, {remote, IP, TEI}}) of
	{Handler, _} when is_pid(Handler) ->
	    gen_server:cast(Handler, {handle_msg, IP, Port, Msg});
	_ ->
	    gtp_u_edp_metrics:measure_request_error(Req, context_not_found),
	    ok
   end;
handle_msg(_Name, _Socket, _Req, IP, Port, #gtp{type = Type, tei = TEI, seq_no = _SeqNo}) ->
    lager:notice("~p from ~p:~w, TEI: ~w, SeqNo: ~w", [Type, IP, Port, TEI, _SeqNo]),
    ok.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Name, Owner,
      #pfcp{type = session_establishment_request,
	    ie = #{f_seid := #f_seid{seid = SEID}} = SER}] = Args) ->
    lager:info("fwd:init(~p)", [Args]),

    gtp_u_edp:register(Name, {seid, SEID}, SEID),
    State0 = #state{owner = Owner, name = Name, seid = SEID},

    try
	State1 = foreach(fun create_pdr/2, State0,
			 maps:get(create_pdr, SER, [])),
	State2 = foreach(fun create_far/2, State1,
			 maps:get(create_far, SER, [])),
	State = foreach(fun create_urr/2, State2,
			maps:get(create_urr, SER, [])),
	{ok, State}
    catch
	error:noproc ->
	    {stop, {error, invalid_port}}
    end.

handle_call(#pfcp{type = session_modification_request, seid = OldSEID, ie = SMR},
	    _From, #state{name = Name} = State0) ->
    case maps:get(f_seid, SMR, undefined) of
	#f_seid{seid = SEID} when is_integer(SEID) andalso OldSEID /= SEID ->
	    gtp_u_edp:unregister(Name, {seid, OldSEID}),
	    gtp_u_edp:register(Name, {seid, SEID}, SEID);
	_ ->
	    ok
    end,

    State1 = foreach(fun update_pdr/2, State0,
		     maps:get(update_pdr, SMR, [])),
    State2 = foreach(fun update_far/2, State1,
		     maps:get(update_far, SMR, [])),
    State = foreach(fun update_urr/2, State2,
		    maps:get(update_urr, SMR, [])),

    Response0 = #pfcp{version = v1, type = session_modification_response, seid = OldSEID,
		      ie = [#pfcp_cause{cause = 'Request accepted'} |
			    query_urr(maps:get(query_urr, SMR, []), State)]},
    Response = pfcp_packet:to_map(Response0),
    {reply, Response, State};

handle_call(#pfcp{type = session_deletion_request, seid = SEID},
	    _From, #state{seid = SEID} = State) ->
    lager:debug("Forwarder: delete session"),

    Response0 = #pfcp{version = v1, type = session_deletion_response, seid = SEID,
		      ie = [#pfcp_cause{cause = 'Request accepted'} |
			    usage_report(usage_report_sdr, State)]},
    Response = pfcp_packet:to_map(Response0),
    {stop, normal, Response, State};

handle_call(_Request, _From, State) ->
    lager:warning("invalid CALL: ~p", [_Request]),
    {reply, error, State}.

handle_cast({handle_msg, PdrId, Req, #gtp{type = g_pdu} = Msg}, State0) ->
    PDR = get_pdr(PdrId, State0),
    FAR = get_far(PDR, State0),
    ForwardAction = get_far_action(FAR),
    State = process_usage_reporting(PdrId, PDR, ForwardAction, Msg, State0),
    process_far(PdrId, FAR, Req, Msg),
    {noreply, State};

handle_cast({handle_msg, IP, _Port, #gtp{type = error_indication} = Msg}, State) ->
    error_indication_report(IP, Msg, State),
    {noreply, State};

handle_cast(stop, State) ->
    lager:debug("Forwarder: STOP"),
    {stop, normal, State};

handle_cast(Msg, State) ->
    lager:debug("Forwarder: unexpected Msg: ~p", [Msg]),
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

ip2bin(IP) when is_binary(IP) ->
    IP;
ip2bin({A, B, C, D}) ->
    <<A, B, C, D>>;
ip2bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

link_port(Name) ->
    RegName = gtp_u_edp_port:port_reg_name(Name),
    case whereis(RegName) of
	Pid when is_pid(Pid) ->
	    link(Pid);
	_ ->
	    error(noproc),
	    %% not reached, silence bogus warning
	    Pid = undefined
    end,
    Pid.

foreach(Fun, Acc, List) when is_list(List) ->
    lists:foldl(Fun, Acc, List);
foreach(Fun, Acc, Term) ->
    Fun(Term, Acc).

get_urr_id(#{urr_id := #urr_id{id = UrrId}}) ->
    [UrrId];
get_urr_id(#{urr_id := UrrIds})
  when is_list(UrrIds) ->
    [UrrId || #urr_id{id = UrrId} <- UrrIds];
get_urr_id(_) ->
    [].

network_instance(Name) when is_list(Name) ->
    BinName = iolist_to_binary([lists:join($., Name)]),
    binary_to_existing_atom(BinName, latin1).

bin2ip(IP) when is_tuple(IP) ->
    IP;
bin2ip(<<A,B,C,D>>) ->
    {A,B,C,D};
bin2ip(<<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>) ->
    {A,B,C,D,E,F,G,H}.

create_pdr(
  #create_pdr{
     group =
	 #{pdr_id := #pdr_id{id = PdrId},
	   pdi :=
	       #pdi{
		  group = #{
		    source_interface := #source_interface{interface = SrcIf},
		    network_instance := #network_instance{instance = InNI},
		    f_teid := #f_teid{teid = TEI}
		   }
		 },
	   outer_header_removal :=
	       #outer_header_removal{header = 'GTP-U/UDP/IPv4'},
	   far_id := #far_id{id = FarId}
	  } = CreatePDR},
  #state{pdr = PDRs} = State) ->
    InPortName = network_instance(InNI),
    PDR = #pdr{
	     name = InPortName,
	     pid = link_port(InPortName),
	     src_if = SrcIf,
	     tei = TEI,
	     far_id = FarId,
	     urr_id = get_urr_id(CreatePDR)
	    },
    gtp_u_edp:register(InPortName, TEI, PdrId),
    State#state{pdr = PDRs#{PdrId => PDR}}.

update_pdr(
  #update_pdr{
     group =
	 #{pdr_id := #pdr_id{id = PdrId},
	   pdi :=
	       #pdi{
		  group = #{
		    source_interface := #source_interface{interface = SrcIf},
		    network_instance := #network_instance{instance = InNI},
		    f_teid := #f_teid{teid = TEI}
		   }
		 },
	   outer_header_removal :=
	       #outer_header_removal{header = 'GTP-U/UDP/IPv4'},
	   far_id := #far_id{id = FarId}
	  } = UpdPDR},
  #state{pdr = PDRs} = State) ->
    #pdr{name = OldInPortName, tei = OldTEI} = maps:get(PdrId, PDRs),
    gtp_u_edp:unregister(OldInPortName, OldTEI),
    InPortName = network_instance(InNI),
    PDR = #pdr{
	     name = InPortName,
	     pid = link_port(InPortName),
	     src_if = SrcIf,
	     tei = TEI,
	     far_id = FarId,
	     urr_id = get_urr_id(UpdPDR)
	    },
    gtp_u_edp:register(InPortName, TEI, PdrId),
    State#state{pdr = PDRs#{PdrId := PDR}}.

create_far(
  #create_far{
     group =
	 #{far_id := #far_id{id = FarId},
	   apply_action := #apply_action{forw = 1},
	   forwarding_parameters :=
	       #forwarding_parameters{
		  group = #{
		    destination_interface := #destination_interface{interface = DstIf},
		    network_instance := #network_instance{instance = OutNI},
		    outer_header_creation :=
			#outer_header_creation{
			   type = 'GTP-U/UDP/IPv4',
			   teid = TEI,
			   address = BinIP
			  }
		    }
		 }
	  }
    },
  #state{far = FARs} = State) ->
    OutPortName = network_instance(OutNI),
    IP = bin2ip(BinIP),
    FAR = #far{
	     name = OutPortName,
	     pid = link_port(OutPortName),
	     dst_if = DstIf,
	     action = forward,
	     ip = IP,
	     tei = TEI
	    },
    gtp_u_edp:register(OutPortName, {remote, IP, TEI}, undefined),
    State#state{far = FARs#{FarId => FAR}}.

update_far(
  #update_far{
     group =
	 #{far_id := #far_id{id = FarId},
	   apply_action := #apply_action{forw = 1},
	   update_forwarding_parameters :=
	       #update_forwarding_parameters{
		  group = #{
		    destination_interface := #destination_interface{interface = DstIf},
		    network_instance := #network_instance{instance = OutNI},
		    outer_header_creation :=
			#outer_header_creation{
			   type = 'GTP-U/UDP/IPv4',
			   teid = TEI,
			   address = BinIP
			  }
		   } = UpdFARParam
		 }
	  }
    },
  #state{far = FARs} = State) ->
    #far{name = OldOutPortName, ip = OldIP, tei = OldTEI} = maps:get(FarId, FARs),
    gtp_u_edp:unregister(OldOutPortName, {remote, OldIP, OldTEI}),
    OutPortName = network_instance(OutNI),
    IP = bin2ip(BinIP),
    FAR = #far{
	     name = OutPortName,
	     pid = link_port(OutPortName),
	     dst_if = DstIf,
	     action = forward,
	     ip = IP,
	     tei = TEI
	    },
    gtp_u_edp:register(OutPortName, {remote, IP, TEI}, undefined),

    case UpdFARParam of
	#{sxsmreq_flags := #sxsmreq_flags{sndem = 1}} ->
	    send_end_marker(OldOutPortName, OldIP, OldTEI),
	    ok;
	_ ->
	    ok
    end,
    State#state{far = FARs#{FarId := FAR}}.

create_urr(
  #create_urr{
     group =
	 #{urr_id :=
	       #urr_id{id = UrrId}} = URR},
  #state{urr = URRs} = State) ->
    State#state{urr = URRs#{UrrId => URR}}.

update_urr(
  #update_urr{
     group =
	 #{urr_id := #urr_id{id = UrrId}} = URR},
  #state{urr = URRs} = State) ->
    %% TODO: keep old counter state ????
    State#state{urr = URRs#{UrrId => URR}}.

query_urr(Query, #state{urr = URRs}) ->
    UrrIds = [Id || #query_urr{group = #{urr_id := #urr_id{id = Id}}} <- Query],
    maps:fold(fun(K,V,Acc) -> usage_report(usage_report_smr, K, V, Acc) end,
	      [], maps:with(UrrIds, URRs)).

get_pdr(PdrId, #state{pdr = PDRs}) ->
    maps:get(PdrId, PDRs, undefined).

get_far(#pdr{far_id = FarId}, #state{far = FARs}) ->
    maps:get(FarId, FARs, undefined);
get_far(_, _) ->
    undefined.

get_urr(UrrId, #state{urr = URRs}) ->
    maps:get(UrrId, URRs, undefined);
get_urr(_, _) ->
    undefined.

update_urr(UrrId, URR, #state{urr = URRs} = State) ->
    State#state{urr = URRs#{UrrId := URR}}.

process_usage_reporting(PdrId, #pdr{src_if = SrcIf, urr_id = UrrIds},
			ForwardAction, Msg, State) ->
    lists:foldl(fun(UrrId, StateIn) ->
			URR = process_urr(PdrId, SrcIf, ForwardAction,
					  get_urr(UrrId, StateIn), Msg),
			update_urr(UrrId, URR, StateIn)
		end, State, UrrIds).

-define(IS_SRC_UL_IntF(X), (X =:= 'Access')).
-define(IS_SRC_DL_IntF(X), (X =:= 'Core')).

update_counter(Add, {Bytes, Pkts}) ->
    {Bytes + Add, Pkts + 1}.

count_traffic(SrcIf, drop, Size,
	      #counter{dropped_dl = Cnt} = Counter)
  when ?IS_SRC_DL_IntF(SrcIf) ->
    Counter#counter{dropped_dl = update_counter(Size, Cnt)};
count_traffic(SrcIf, drop, Size,
	      #counter{dropped_ul = Cnt} = Counter)
  when ?IS_SRC_UL_IntF(SrcIf) ->
    Counter#counter{dropped_ul = update_counter(Size, Cnt)};
count_traffic(SrcIf, forward, Size,
	      #counter{dl = Cnt, total = Total} = Counter)
  when ?IS_SRC_DL_IntF(SrcIf) ->
    Counter#counter{dl = update_counter(Size, Cnt),
		    total = update_counter(Size, Total)};
count_traffic(SrcIf, forward, Size,
	      #counter{ul = Cnt, total = Total} = Counter)
  when ?IS_SRC_UL_IntF(SrcIf) ->
    Counter#counter{ul = update_counter(Size, Cnt),
		    total = update_counter(Size, Total)};
count_traffic(_SrcIf, _ForwardAction, _Size, Counter) ->
    Counter.

count_urr(SrcIf, ForwardAction, URR, #gtp{ie = Data}) ->
    Counter0 = maps:get(counter, URR, #counter{}),
    Counter = count_traffic(SrcIf, ForwardAction, size(Data), Counter0),
    URR#{counter => Counter}.

process_urr(_PdrId, SrcIf, ForwardAction, URR0, Msg)
  when is_map(URR0) ->
    URR = count_urr(SrcIf, ForwardAction, URR0, Msg),
    URR;
process_urr(_PdrId, _SrcIf, _ForwardAction, URR, _Msg) ->
    URR.

get_far_action(#far{action = Action}) ->
    Action;
get_far_action(_) ->
    drop.

process_far(_PdrId, #far{pid = Pid, action = forward, ip = IP, tei = TEI}, Req, Msg) ->
    Data = gtp_packet:encode(Msg#gtp{tei = TEI}),
    gtp_u_edp_port:send(Pid, Req, IP, Data);
process_far(_PdrId, _FAR, _Req, _Msg) ->
    lager:debug("dropping packet with invalid FAR: ~p, ~p", [_Msg, _FAR]),
    ok.

error_indication_report(IP, #gtp{ie = IEs},
			#state{owner = Owner, seid = SEID}) ->
    #tunnel_endpoint_identifier_data_i{tei = TEI} =
	maps:get(?'Tunnel Endpoint Identifier Data I', IEs),
    SRR =
	[#report_type{erir = 1},
	 #error_indication_report{
	    group = [#f_teid{ipv4 = ip2bin(IP), teid = TEI}]}],
    Request = #pfcp{version = v1, type = session_report_request,
		    seid = SEID, ie = SRR},
    Owner ! pfcp_packet:to_map(Request).

urr_volume_report(Type, UrrId,
		  #counter{dl = {DLBytes, DLPkts},
			   ul = {ULBytes, ULPkts},
			   total = {Bytes, Pkts}
			  }) ->
    {Type, [#urr_id{id = UrrId},
	    #volume_measurement{total = Bytes, uplink = ULBytes, downlink = DLBytes},
	    #tp_packet_measurement{total = Pkts, uplink = ULPkts, downlink = DLPkts}]}.

usage_report(Type, UrrId, #{
		     measurement_method := #measurement_method{volum = 1},
		     counter := Counter}, Reports) ->
    UR = urr_volume_report(Type, UrrId, Counter),
    [UR | Reports];
usage_report(_, _, _, Reports) ->
    Reports.

usage_report(Type, #state{urr = URRs}) ->
    maps:fold(fun(K,V,Acc) -> usage_report(Type,K,V,Acc) end, [], URRs).

send_end_marker(PortName, IP, TEI) ->
    RegName = gtp_u_edp_port:port_reg_name(PortName),
    case whereis(RegName) of
	Pid when is_pid(Pid) ->
	    gtp_u_edp_port:send_end_marker(Pid, IP, TEI);
	_ ->
	    ok
    end.
