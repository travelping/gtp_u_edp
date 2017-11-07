%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp_forwarder).

-behaviour(gen_server).

%% API
-export([start_link/4, create_session/4]).
-export([handle_msg/6]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("gtplib/include/gtp_packet.hrl").
-include("include/gtp_u_edp.hrl").

-define(SERVER, ?MODULE).
-define('Tunnel Endpoint Identifier Data I',	{tunnel_endpoint_identifier_data_i, 0}).
-define('GTP-U Peer Address',			{gsn_address, 0}).

-record(pdr, {name, pid, tei, far_id}).
-record(far, {name, pid, ip, tei}).

-record(state, {
	  owner,
	  name,
	  seid,
	  pdr = #{},
	  far = #{}
	 }).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Name, Owner, SEID, SER) ->
    gen_server:start_link(?MODULE, [Name, Owner, SEID, SER], []).

create_session(Name, Owner, SEID, SER) ->
    gtp_u_edp_handler_sup:create_session(Name, Owner, SEID, SER).

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

init([Name, Owner, SEID, SER] = Args) ->
    lager:info("fwd:init(~p)", [Args]),

    gtp_u_edp:register(Name, {seid, SEID}, SEID),
    State0 = #state{owner = Owner, name = Name, seid = SEID},

    try
	State1 = lists:foldl(fun create_pdr/2, State0,
			     maps:get(create_pdr, SER, [])),
	State = lists:foldl(fun create_far/2, State1,
			    maps:get(create_far, SER, [])),
	{ok, State}
    catch
	error:noproc ->
	    {stop, {error, invalid_port}}
    end.

handle_call({OldSEID, session_modification_request, SMR},
	    _From, #state{name = Name} = State0) ->
    case maps:get(cp_f_seid, SMR, undefined) of
	SEID when is_integer(SEID) andalso OldSEID /= SEID ->
	    gtp_u_edp:unregister(Name, {seid, OldSEID}),
	    gtp_u_edp:register(Name, {seid, SEID}, SEID);
	_ ->
	    ok
    end,

    State1 = lists:foldl(fun update_pdr/2, State0,
			 maps:get(update_pdr, SMR, [])),
    State = lists:foldl(fun update_far/2, State1,
			maps:get(update_far, SMR, [])),
    {reply, ok, State};

handle_call({SEID, session_deletion_request, _}, _From, #state{seid = SEID} = State) ->
    lager:debug("Forwarder: delete session"),
    {stop, normal, ok, State};

handle_call(_Request, _From, State) ->
    lager:warning("invalid CALL: ~p", [_Request]),
    {reply, error, State}.

handle_cast({handle_msg, PdrId, Req, #gtp{type = g_pdu} = Msg}, State) ->
    process_far(PdrId, get_far(PdrId, State), Req, Msg),
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

create_pdr(#{pdr_id := PdrId,
	     pdi := #{
	       source_interface := InPortName,
	       local_f_teid := #f_teid{teid = TEI}
	      },
	     outer_header_removal := true,
	     far_id := FarId},
	   #state{pdr = PDRs} = State) ->
    PDR = #pdr{
	     name = InPortName,
	     pid = link_port(InPortName),
	     tei = TEI,
	     far_id = FarId
	    },
    gtp_u_edp:register(InPortName, TEI, PdrId),
    State#state{pdr = PDRs#{PdrId => PDR}}.

update_pdr(#{pdr_id := PdrId,
	     pdi := #{
	       source_interface := InPortName,
	       local_f_teid := #f_teid{teid = TEI}
	      },
	     outer_header_removal := true,
	     far_id := FarId},
	   #state{pdr = PDRs} = State) ->
    #pdr{name = OldInPortName, tei = OldTEI} = maps:get(PdrId, PDRs),
    gtp_u_edp:unregister(OldInPortName, OldTEI),
    PDR = #pdr{
	     name = InPortName,
	     pid = link_port(InPortName),
	     tei = TEI,
	     far_id = FarId
	    },
    gtp_u_edp:register(InPortName, TEI, PdrId),
    State#state{pdr = PDRs#{PdrId := PDR}}.

create_far(#{far_id := FarId,
	     apply_action := [forward],
	     forwarding_parameters := #{
	       destination_interface := OutPortName,
	       outer_header_creation := #f_teid{ipv4 = IP, teid = TEI}
	      }},
	   #state{far = FARs} = State) ->
    FAR = #far{
	     name = OutPortName,
	     pid = link_port(OutPortName),
	     ip = IP,
	     tei = TEI
	    },
    gtp_u_edp:register(OutPortName, {remote, IP, TEI}, undefined),
    State#state{far = FARs#{FarId => FAR}}.

update_far(#{far_id := FarId,
	     apply_action := [forward],
	     update_forwarding_parameters := #{
	       destination_interface := OutPortName,
	       outer_header_creation := #f_teid{ipv4 = IP, teid = TEI}
	      }} = UpdFAR,
	   #state{far = FARs} = State) ->
    #far{name = OldOutPortName, ip = OldIP, tei = OldTEI} = maps:get(FarId, FARs),
    gtp_u_edp:unregister(OldOutPortName, {remote, OldIP, OldTEI}),
    FAR = #far{
	     name = OutPortName,
	     pid = link_port(OutPortName),
	     ip = IP,
	     tei = TEI
	    },
    gtp_u_edp:register(OutPortName, {remote, IP, TEI}, undefined),

    SxSMReqFlags = maps:get(sxsmreq_flags, UpdFAR, []),
    case proplists:get_bool(sndem, SxSMReqFlags) of
	true ->
	    send_end_marker(OldOutPortName, OldIP, OldTEI),
	    ok;
	_ ->
	    ok
    end,
    State#state{far = FARs#{FarId := FAR}}.

get_far(PdrId, #state{pdr = PDRs, far = FARs}) ->
    case PDRs of
	#{PdrId := #pdr{far_id = FarId}} ->
	    maps:get(FarId, FARs, undefined);
	_ ->
	    undefined
    end.

process_far(_PdrId, #far{pid = Pid, ip = IP, tei = TEI}, Req, Msg) ->
    Data = gtp_packet:encode(Msg#gtp{tei = TEI}),
    gtp_u_edp_port:send(Pid, Req, IP, Data);
process_far(_PdrId, _FAR, _Req, _Msg) ->
    lager:debug("dropping packet with invalid FAR: ~p, ~p", [_Msg, _FAR]),
    ok.

error_indication_report(IP, #gtp{ie = IEs},
			#state{owner = Owner, seid = SEID}) ->
    #tunnel_endpoint_identifier_data_i{tei = TEI} =
	maps:get(?'Tunnel Endpoint Identifier Data I', IEs),
    FTEID = #f_teid{ipv4 = IP, teid = TEI},
    SRR = #{
      report_type => [error_indication_report],
      error_indication_report =>
	  [#{remote_f_teid => FTEID}]
     },
    Owner ! {SEID, session_report_request, SRR}.

send_end_marker(PortName, IP, TEI) ->
    RegName = gtp_u_edp_port:port_reg_name(PortName),
    case whereis(RegName) of
	Pid when is_pid(Pid) ->
	    gtp_u_edp_port:send_end_marker(Pid, IP, TEI);
	_ ->
	    ok
    end.
