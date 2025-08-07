# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController, IContextMenuFactory
from javax.swing import JPanel, JTable, JScrollPane, JSplitPane, JButton, JTextField, JLabel, JMenuItem, JTextArea
from javax.swing.table import DefaultTableModel, TableRowSorter, AbstractTableModel
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import MouseAdapter
import java.lang
import json
from datetime import datetime
import re
from threading import Lock

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Next.js Server Actions Analyzer (Enhanced)")
        
        # Thread safety
        self._lock = Lock()
        
        # Create UI
        self._main_panel = JPanel(BorderLayout())
        
        # Create main tabbed pane for different views
        from javax.swing import JTabbedPane
        self._main_tabbed_pane = JTabbedPane()
        
        # Tab 1: All Requests View
        self._requests_panel = JPanel(BorderLayout())
        
        # Create control panel for requests view
        control_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        
        # Add filter controls
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.insets = Insets(5, 5, 5, 5)
        control_panel.add(JLabel("Action Filter:"), gbc)
        
        gbc.gridx = 1
        self._action_filter = JTextField(20)
        # Add document listener for real-time filtering
        from javax.swing.event import DocumentListener
        class FilterListener(DocumentListener):
            def __init__(self, extender):
                self.extender = extender
            def insertUpdate(self, e):
                self.extender.apply_filter()
            def removeUpdate(self, e):
                self.extender.apply_filter()
            def changedUpdate(self, e):
                self.extender.apply_filter()
        
        self._action_filter.getDocument().addDocumentListener(FilterListener(self))
        control_panel.add(self._action_filter, gbc)
        
        gbc.gridx = 2
        scan_history_button = JButton("Scan Proxy History", actionPerformed=self.scan_proxy_history)
        control_panel.add(scan_history_button, gbc)
        
        gbc.gridx = 3
        clear_button = JButton("Clear", actionPerformed=self.clear_table)
        control_panel.add(clear_button, gbc)
        
        gbc.gridx = 4
        export_button = JButton("Export Analysis", actionPerformed=self.export_actions)
        control_panel.add(export_button, gbc)
        
        gbc.gridx = 5
        extract_names_button = JButton("Extract Action Names", actionPerformed=self.extract_action_names)
        control_panel.add(extract_names_button, gbc)
        
        gbc.gridx = 6
        find_unused_button = JButton("Find Unused Actions", actionPerformed=self.find_all_actions)
        control_panel.add(find_unused_button, gbc)
        
        self._requests_panel.add(control_panel, BorderLayout.NORTH)
        
        # Create table for Server Actions
        self._table_model = DefaultTableModel()
        self._table_model.addColumn("ID")
        self._table_model.addColumn("Method")
        self._table_model.addColumn("URL")
        self._table_model.addColumn("Action ID")
        self._table_model.addColumn("Parameters")
        self._table_model.addColumn("Req Size")
        self._table_model.addColumn("Res Size")
        self._table_model.addColumn("Status")
        self._table_model.addColumn("Timestamp")
        self._table_model.addColumn("Security Notes")
        self._table_model.addColumn("Action Notes")
        
        self._actions_table = JTable(self._table_model)
        self._actions_table.setAutoCreateRowSorter(True)
        
        # Add right-click listener for the table
        from java.awt.event import MouseListener
        self._actions_table.addMouseListener(TableMouseListener(self))
        
        # Create split pane
        table_scroll = JScrollPane(self._actions_table)
        self._request_viewer = callbacks.createMessageEditor(self, False)
        self._response_viewer = callbacks.createMessageEditor(self, False)
        
        # Side-by-side request/response panel
        req_res_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        req_res_split.setLeftComponent(self._request_viewer.getComponent())
        req_res_split.setRightComponent(self._response_viewer.getComponent())
        req_res_split.setResizeWeight(0.5)
        
        # Notes panel
        self._notes_area = JTextArea(3, 30)
        self._notes_area.setLineWrap(True)
        self._notes_area.setWrapStyleWord(True)
        notes_scroll = JScrollPane(self._notes_area)
        
        save_notes_button = JButton("Save Notes", actionPerformed=self.save_notes)
        notes_panel = JPanel(BorderLayout())
        notes_panel.add(JLabel("Action Notes (applies to all requests with this Action ID):"), BorderLayout.NORTH)
        notes_panel.add(notes_scroll, BorderLayout.CENTER)
        notes_panel.add(save_notes_button, BorderLayout.SOUTH)
        
        # Request/Response viewer tabs
        from javax.swing import JTabbedPane
        viewer_tabs = JTabbedPane()
        viewer_tabs.addTab("Request/Response", req_res_split)
        viewer_tabs.addTab("Notes", notes_panel)
        
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, viewer_tabs)
        split_pane.setResizeWeight(0.5)
        
        self._requests_panel.add(split_pane, BorderLayout.CENTER)
        
        # Tab 2: Action Discovery View
        self._discovery_panel = JPanel(BorderLayout())
        
        # Discovery control panel
        discovery_control_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.insets = Insets(5, 5, 5, 5)
        discovery_control_panel.add(JLabel("Status:"), gbc)
        
        gbc.gridx = 1
        self._discovery_status = JLabel("Not scanned yet")
        discovery_control_panel.add(self._discovery_status, gbc)
        
        gbc.gridx = 2
        discovery_scan_button = JButton("Scan for All Actions", actionPerformed=self.find_all_actions)
        discovery_control_panel.add(discovery_scan_button, gbc)
        
        gbc.gridx = 3
        discovery_refresh_button = JButton("Refresh View", actionPerformed=self.refresh_discovery)
        discovery_control_panel.add(discovery_refresh_button, gbc)
        
        self._discovery_panel.add(discovery_control_panel, BorderLayout.NORTH)
        
        # Create discovery sub-tabs
        discovery_tabs = JTabbedPane()
        
        # All discovered actions table
        class DiscoveryTableModel(AbstractTableModel):
            def __init__(self):
                self.columns = ["Action ID", "Function Name", "Status", "Chunk File", "Executed Count", "Notes"]
                self.data = []
                
            def getColumnCount(self):
                return len(self.columns)
                
            def getRowCount(self):
                return len(self.data)
                
            def getColumnName(self, col):
                return self.columns[col]
                
            def getValueAt(self, row, col):
                return self.data[row][col]
                
            def getColumnClass(self, col):
                if col == 4:  # Executed Count
                    return java.lang.Integer
                return java.lang.String
                
            def addRow(self, row_data):
                self.data.append(row_data)
                self.fireTableRowsInserted(len(self.data) - 1, len(self.data) - 1)
                
            def setRowCount(self, count):
                if count == 0:
                    self.data = []
                    self.fireTableDataChanged()
        
        # All actions table
        self._all_actions_model = DiscoveryTableModel()
        self._all_actions_table = JTable(self._all_actions_model)
        self._all_actions_table.setAutoCreateRowSorter(True)
        all_actions_scroll = JScrollPane(self._all_actions_table)
        
        # Unused actions table
        self._unused_actions_model = DiscoveryTableModel()
        self._unused_actions_table = JTable(self._unused_actions_model)
        self._unused_actions_table.setAutoCreateRowSorter(True)
        unused_actions_scroll = JScrollPane(self._unused_actions_table)
        
        # Unknown actions table (executed but not found in chunks)
        self._unknown_actions_model = DiscoveryTableModel()
        self._unknown_actions_table = JTable(self._unknown_actions_model)
        self._unknown_actions_table.setAutoCreateRowSorter(True)
        unknown_actions_scroll = JScrollPane(self._unknown_actions_table)
        
        # Add mouse listeners for context menus on discovery tables
        self._all_actions_table.addMouseListener(DiscoveryTableMouseListener(self, self._all_actions_table))
        self._unused_actions_table.addMouseListener(DiscoveryTableMouseListener(self, self._unused_actions_table))
        self._unknown_actions_table.addMouseListener(DiscoveryTableMouseListener(self, self._unknown_actions_table))
        
        discovery_tabs.addTab("All Discovered Actions", all_actions_scroll)
        discovery_tabs.addTab("Unused Actions", unused_actions_scroll)
        discovery_tabs.addTab("Unknown Actions", unknown_actions_scroll)
        
        self._discovery_panel.add(discovery_tabs, BorderLayout.CENTER)
        
        # Add tabs to main panel
        self._main_tabbed_pane.addTab("All Requests", self._requests_panel)
        self._main_tabbed_pane.addTab("Action Discovery", self._discovery_panel)
        
        self._main_panel.add(self._main_tabbed_pane, BorderLayout.CENTER)
        
        # Table selection listener
        self._actions_table.getSelectionModel().addListSelectionListener(
            lambda e: self.table_selection_changed()
        )
        
        # Track requests and action notes
        self._actions = []
        self._action_map = {}  # Map action IDs to their usage
        self._action_notes = {}  # Map action IDs to user notes
        self._action_names = {}  # Map action IDs to function names from chunks
        self._all_discovered_actions = {}  # NEW: Map ALL discovered action IDs to their info
        self._request_id = 0
        self._current_action_id = None
        self._chunk_responses = []  # Store chunk responses for searching
        
        # Register callbacks
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        # Initialize action patterns - only Server Actions
        self._action_pattern = re.compile(r'Next-Action:\s*([a-f0-9]+)', re.IGNORECASE)
        
        # Statistics tracking
        self._stats = {
            'total_actions': 0,
            'unique_actions': set(),
            'post_actions': 0,
            'get_actions': 0,
            'auth_missing': 0,
            'errors_exposed': 0
        }
        
        print("Next.js Server Actions Analyzer (Enhanced) loaded successfully!")
    
    def getTabCaption(self):
        return "Next.js Actions"
    
    def getUiComponent(self):
        return self._main_panel
    
    def createMenuItems(self, invocation):
        menu_items = []
        context = invocation.getInvocationContext()
        
        if context == invocation.CONTEXT_PROXY_HISTORY:
            menu_item = JMenuItem("Analyze for Next.js Actions", actionPerformed=lambda e: self.analyze_selected_items(invocation))
            menu_items.append(menu_item)
            
            lookup_item = JMenuItem("Lookup Server Action Name", actionPerformed=lambda e: self.lookup_action_for_request(invocation))
            menu_items.append(lookup_item)
            
        elif context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or context == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            # Check if we're in our extension tab
            selected_row = self._actions_table.getSelectedRow()
            if selected_row >= 0:
                menu_items.append(JMenuItem("Send to Repeater", actionPerformed=lambda e: self.send_to_repeater()))
                menu_items.append(JMenuItem("Send to Intruder", actionPerformed=lambda e: self.send_to_intruder()))
                menu_items.append(JMenuItem("Send to Intruder (Fuzz Parameters)", actionPerformed=lambda e: self.send_to_intruder_with_positions()))
                
        return menu_items
    
    def analyze_selected_items(self, invocation):
        for message in invocation.getSelectedMessages():
            self.processHttpMessage(0, False, message)
    
    def lookup_action_for_request(self, invocation):
        """Lookup server action name for selected requests and add to Burp note field"""
        messages = invocation.getSelectedMessages()
        
        for message in messages:
            request_info = self._helpers.analyzeRequest(message)
            
            # Extract action ID from request
            action_id = self._extract_action_id(message)
            
            if action_id and action_id in self._action_names:
                function_name = self._action_names[action_id]
                
                # Get current note
                current_note = message.getComment() or ""
                
                # Add function name to note if not already present
                function_text = "Server Action: " + function_name
                if function_text not in current_note:
                    if current_note:
                        new_note = current_note + "\n" + function_text
                    else:
                        new_note = function_text
                    
                    # Update the note in Burp
                    message.setComment(new_note)
                    
                    print("Added server action to note: " + function_name + " for action ID: " + action_id)
                else:
                    print("Server action already in note: " + function_name)
            else:
                if action_id:
                    print("No server action name found for action ID: " + action_id)
                    print("Try running 'Extract Action Names' first to scan chunk files")
                else:
                    print("No Next.js action ID found in request")
    
    def scan_proxy_history(self, event):
        # Scan all proxy history for Next.js actions
        proxy_history = self._callbacks.getProxyHistory()
        count = 0
        
        for message in proxy_history:
            if message.getResponse():
                self.processHttpMessage(0, False, message)
                count += 1
        
        print("Scanned " + str(count) + " requests from proxy history")
        
        # Auto-update action discovery after scanning
        print("Auto-updating action discovery...")
        self.find_all_actions(None)
    
    def find_all_actions(self, event):
        """NEW METHOD: Find ALL server actions in JavaScript chunks, not just executed ones"""
        print("\n=== Scanning for ALL Next.js Server Actions ===")
        self._discovery_status.setText("Scanning chunks...")
        
        proxy_history = self._callbacks.getProxyHistory()
        chunks_found = 0
        total_actions_found = 0
        
        # Clear previous discoveries
        self._all_discovered_actions.clear()
        
        # Enhanced patterns for finding server actions
        patterns = [
            # Pattern 1 - Standard format
            re.compile(r'createServerReference\)\("([a-f0-9]{40,})",\w+\.callServer,void 0,\w+\.findSourceMapURL,"([^"]+)"\)'),
            # Pattern 2 - With (0,obj.method) format
            re.compile(r'\(\d+,\s*\w+\.createServerReference\)\s*\(\s*"([a-f0-9]{40,})",\s*\w+\.callServer,\s*void\s+0,\s*\w+\.findSourceMapURL,\s*"([^"]+)"\s*\)'),
            # Pattern 3 - More flexible spacing
            re.compile(r'createServerReference\)\s*\(\s*"([a-f0-9]{40,})",\s*\w+\.callServer,\s*void\s+0,\s*\w+\.findSourceMapURL,\s*"([^"]+)"\s*\)'),
            # Pattern 4 - Handle any number of parameters
            re.compile(r'createServerReference[^"]*"([a-f0-9]{40,})"[^"]*"([^"]+)"\s*\)')
        ]
        
        # Process proxy history
        for message in proxy_history:
            if message.getResponse():
                request_info = self._helpers.analyzeRequest(message)
                url = str(request_info.getUrl())
                
                # Check if this is a chunk file
                if '/_next/static/chunks/' in url and '.js' in url.split('?')[0]:
                    chunk_name = url.split('/')[-1].split('?')[0]
                    
                    # Get response body
                    response = message.getResponse()
                    response_info = self._helpers.analyzeResponse(response)
                    body_offset = response_info.getBodyOffset()
                    response_body = self._helpers.bytesToString(response[body_offset:])
                    
                    # Only process if it contains createServerReference
                    if 'createServerReference' in response_body:
                        chunks_found += 1
                        print("\nScanning chunk: " + chunk_name)
                        
                        # Store chunk response for later searching
                        self._chunk_responses.append({
                            'url': url,
                            'message': message,
                            'body': response_body
                        })
                        
                        # Try all patterns
                        chunk_actions = set()
                        for i, pattern in enumerate(patterns):
                            matches = pattern.findall(response_body)
                            for match in matches:
                                hash_part = match[0]
                                name_part = match[1]
                                
                                # Validate that this looks like a real server action
                                if (len(hash_part) >= 40 and 
                                    len(name_part) > 1 and 
                                    not name_part.startswith('$') and  # Skip internal functions
                                    not name_part.startswith('_')):    # Skip private functions
                                    
                                    if hash_part not in self._all_discovered_actions:
                                        self._all_discovered_actions[hash_part] = {
                                            'function_name': name_part,
                                            'chunk_file': chunk_name,
                                            'first_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                            'message_info': message  # Store the message for navigation
                                        }
                                        chunk_actions.add(hash_part)
                                        total_actions_found += 1
                        
                        if chunk_actions:
                            print("  Found " + str(len(chunk_actions)) + " unique actions in this chunk")
        
        # Analyze discovered vs executed actions
        executed_actions = self._stats['unique_actions']
        all_discovered = set(self._all_discovered_actions.keys())
        unused_actions = all_discovered - executed_actions
        unknown_actions = executed_actions - all_discovered
        
        print("\n=== Server Action Discovery Complete! ===")
        print("Scanned " + str(chunks_found) + " chunk files")
        print("Total server actions discovered: " + str(len(all_discovered)))
        print("Executed actions: " + str(len(executed_actions)))
        print("UNUSED actions (never executed): " + str(len(unused_actions)))
        print("Unknown actions (executed but not found in chunks): " + str(len(unknown_actions)))
        
        # Update status
        status = "Found " + str(len(all_discovered)) + " actions (" + str(len(unused_actions)) + " unused)"
        self._discovery_status.setText(status)
        
        # Update the action names for known actions
        for action_id, info in self._all_discovered_actions.items():
            if action_id not in self._action_names:
                self._action_names[action_id] = info['function_name']
                
                # Update notes for existing actions
                if action_id in self._action_notes:
                    existing_note = self._action_notes[action_id]
                    if info['function_name'] not in existing_note:
                        self._action_notes[action_id] = "Function: " + info['function_name'] + "\n" + existing_note
                else:
                    self._action_notes[action_id] = "Function: " + info['function_name']
        
        # Refresh discovery view
        self.refresh_discovery(None)
        
        # Switch to discovery tab
        self._main_tabbed_pane.setSelectedIndex(1)
    
    def refresh_discovery(self, event):
        """Refresh the discovery view tables"""
        # Clear existing data
        self._all_actions_model.setRowCount(0)
        self._unused_actions_model.setRowCount(0)
        self._unknown_actions_model.setRowCount(0)
        
        executed_actions = self._stats['unique_actions']
        
        # Build a map of function names to action IDs (both discovered and executed)
        function_name_map = {}
        for action_id, info in self._all_discovered_actions.items():
            func_name = info['function_name']
            if func_name not in function_name_map:
                function_name_map[func_name] = []
            function_name_map[func_name].append(action_id)
        
        # Also add executed actions with known names
        for action_id in executed_actions:
            if action_id in self._action_names:
                func_name = self._action_names[action_id]
                if func_name not in function_name_map:
                    function_name_map[func_name] = []
                if action_id not in function_name_map[func_name]:
                    function_name_map[func_name].append(action_id)
        
        # Debug: Print function names with multiple IDs
        for func_name, ids in function_name_map.items():
            if len(ids) > 1:
                executed_count = sum(1 for aid in ids if aid in executed_actions)
                print("Function '" + func_name + "' has " + str(len(ids)) + " IDs, " + str(executed_count) + " executed")
        
        # Populate all actions table
        for action_id, info in self._all_discovered_actions.items():
            exec_count = len(self._action_map.get(action_id, []))
            
            # Determine status with multi-level logic
            if action_id in executed_actions:
                status = "Used"
            else:
                # Check if function name has been used with different ID
                func_name = info['function_name']
                related_ids = function_name_map.get(func_name, [])
                used_ids = [aid for aid in related_ids if aid in executed_actions and aid != action_id]
                
                if used_ids:
                    # This function name HAS been executed, just with a different ID
                    if len(related_ids) > 1:
                        status = "Possibly Used (Multiple IDs)"
                    else:
                        status = "Possibly Used"
                else:
                    # This function name has NEVER been executed
                    if len(related_ids) > 1:
                        status = "Unused (Multiple IDs)"
                    else:
                        status = "Unused"
            
            self._all_actions_model.addRow([
                action_id,
                info['function_name'],
                status,
                info['chunk_file'],
                exec_count,
                self._action_notes.get(action_id, "")
            ])
            
            # Add to unused table only if function name was never executed
            func_name = info['function_name']
            related_ids = function_name_map.get(func_name, [])
            has_been_executed = any(aid in executed_actions for aid in related_ids)
            
            if not has_been_executed:
                self._unused_actions_model.addRow([
                    action_id,
                    info['function_name'],
                    status,
                    info['chunk_file'],
                    0,
                    self._action_notes.get(action_id, "")
                ])
        
        # Populate unknown actions table (executed but not found in chunks)
        for action_id in executed_actions:
            if action_id not in self._all_discovered_actions:
                exec_count = len(self._action_map.get(action_id, []))
                self._unknown_actions_model.addRow([
                    action_id,
                    self._action_names.get(action_id, "Unknown"),
                    "Not Found in Chunks",
                    "N/A",
                    exec_count,
                    self._action_notes.get(action_id, "")
                ])
    
    def extract_action_names(self, event):
        """Extract Server Action function names from _next/static/chunks files"""
        print("Scanning proxy history for Next.js chunk files...")
        
        proxy_history = self._callbacks.getProxyHistory()
        chunks_found = 0
        names_extracted = 0
        
        # Based on createServerReference)("hash",D.callServer,void 0,D.findSourceMapURL,"functionName")
        patterns = [
            # Pattern 1 - Matches your exact format
            re.compile(r'createServerReference\)\("([a-f0-9]{40,})",\w+\.callServer,void 0,\w+\.findSourceMapURL,"([^"]+)"\)'),
            # Pattern 2 - Matches (0,eo.createServerReference)("hash",...)
            re.compile(r'\(\d+,\s*\w+\.createServerReference\)\s*\(\s*"([a-f0-9]{40,})",\s*\w+\.callServer,\s*void\s+0,\s*\w+\.findSourceMapURL,\s*"([^"]+)"\s*\)'),
            # Pattern 3 - Even more flexible
            re.compile(r'createServerReference\)\s*\(\s*"([a-f0-9]{40,})",\s*\w+\.callServer,\s*void\s+0,\s*\w+\.findSourceMapURL,\s*"([^"]+)"\s*\)'),
            # Pattern 4 - Most flexible, matches any number of parameters between hash and function name
            re.compile(r'\(\d+,\s*\w+\.createServerReference\)\s*\(\s*"([a-f0-9]{40,})"(?:[^"]*?,){4}\s*"([^"]+)"\s*\)')
        ]

        # Process proxy history
        for message in proxy_history:
            if message.getResponse():
                request_info = self._helpers.analyzeRequest(message)
                url = str(request_info.getUrl())
                
                # Check if this is a chunk file
                if '/_next/static/chunks/' in url and '.js' in url.split('?')[0]:
                    chunks_found += 1
                    chunk_name = url.split('/')[-1]
                    
                    # Get response body
                    response = message.getResponse()
                    response_info = self._helpers.analyzeResponse(response)
                    body_offset = response_info.getBodyOffset()
                    response_body = self._helpers.bytesToString(response[body_offset:])
                    
                    # Only process if it contains createServerReference
                    if 'createServerReference' in response_body:
                        print("\nScanning chunk: " + chunk_name)
                        print("  Found createServerReference in chunk")
                        
                        # Count occurrences
                        count = response_body.count('createServerReference')
                        print("  Total createServerReference occurrences: " + str(count))
                        
                        # Find and show a sample of the actual content
                        index = response_body.find('createServerReference')
                        if index != -1:
                            # Show 100 chars before and 300 after
                            start = max(0, index - 100)
                            end = min(len(response_body), index + 300)
                            sample = response_body[start:end]
                            # Clean up for display
                            sample = sample.replace('\n', ' ').replace('\r', ' ')
                            print("  Sample around createServerReference:")
                            print("  ..." + sample + "...")
                        
                        # Try patterns
                        found_in_chunk = False
                        for i, pattern in enumerate(patterns):
                            matches = pattern.findall(response_body)
                            if matches:
                                print("  Pattern " + str(i+1) + " found " + str(len(matches)) + " matches:")
                                for match in matches[:10]:  # Show up to 10
                                    hash_part = match[0]
                                    name_part = match[1]
                                    
                                    # Check if this looks like a valid function name
                                    if (len(hash_part) >= 40 and 
                                        len(name_part) > 2 and 
                                        name_part[0].islower() and
                                        any(c.isupper() for c in name_part[1:])):  # camelCase
                                        
                                        print("    " + hash_part[:12] + "... => " + name_part)
                                        found_in_chunk = True
                                        
                                        if hash_part not in self._action_names:
                                            self._action_names[hash_part] = name_part
                                            names_extracted += 1
                                            
                                            # Update notes
                                            if hash_part in self._action_notes:
                                                existing_note = self._action_notes[hash_part]
                                                if name_part not in existing_note:
                                                    self._action_notes[hash_part] = "Function: " + name_part + "\n" + existing_note
                                            else:
                                                self._action_notes[hash_part] = "Function: " + name_part
                                            
                                            # Update table
                                            with self._lock:
                                                for j in range(self._table_model.getRowCount()):
                                                    if self._table_model.getValueAt(j, 3) == hash_part:
                                                        self._table_model.setValueAt(self._action_notes[hash_part], j, 10)
                                                
                                                for action in self._actions:
                                                    if action['action_id'] == hash_part:
                                                        action['action_notes'] = self._action_notes[hash_part]
        
        print("\n=== Action name extraction complete! ===")
        print("Scanned " + str(chunks_found) + " chunk files")
        print("Extracted " + str(names_extracted) + " unique action names")
        print("Total known action names: " + str(len(self._action_names)))
        
        if chunks_found > 0 and names_extracted == 0:
            print("\nTroubleshooting: No action names found")
            print("- Check the sample output above to see the actual format")
            print("- The minification might be different than expected")
            print("- You may need to browse more of the application")
        
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest and messageInfo.getResponse():
            request_info = self._helpers.analyzeRequest(messageInfo)
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            
            # Check if this is a Next.js Server Action
            headers = request_info.getHeaders()
            headers_str = '\n'.join(headers)
            
            # Look for Next-Action header
            action_match = self._action_pattern.search(headers_str)
            if action_match:
                action_id = action_match.group(1)
                
                with self._lock:
                    self._request_id += 1
                    self._stats['total_actions'] += 1
                    self._stats['unique_actions'].add(action_id)
                    
                    if request_info.getMethod() == "POST":
                        self._stats['post_actions'] += 1
                    else:
                        self._stats['get_actions'] += 1
                    
                    # Extract parameters
                    params = self._extract_parameters(messageInfo)
                    
                    # Analyze for potential security issues
                    security_notes = self._analyze_security(messageInfo, action_id, params)
                    
                    if "No auth headers" in security_notes:
                        self._stats['auth_missing'] += 1
                    if "Error in response" in security_notes or "DB error exposed" in security_notes:
                        self._stats['errors_exposed'] += 1
                    
                    # Get action-specific notes
                    action_notes = self._action_notes.get(action_id, "")
                    
                    # If we know the function name, add it
                    if action_id in self._action_names and "Function: " + self._action_names[action_id] not in action_notes:
                        if action_notes:
                            action_notes = "Function: " + self._action_names[action_id] + "\n" + action_notes
                        else:
                            action_notes = "Function: " + self._action_names[action_id]
                        self._action_notes[action_id] = action_notes
                    
                    # Get timestamp from response headers if available
                    timestamp = self._get_timestamp(response_info.getHeaders())
                    
                    # Store the action
                    action_data = {
                        'id': self._request_id,
                        'messageInfo': messageInfo,
                        'method': request_info.getMethod(),
                        'url': str(request_info.getUrl()),
                        'action_id': action_id,
                        'parameters': json.dumps(params) if params else "{}",
                        'request_size': len(messageInfo.getRequest()),
                        'response_size': len(messageInfo.getResponse()),
                        'status': response_info.getStatusCode(),
                        'timestamp': timestamp,
                        'security_notes': security_notes,
                        'action_notes': action_notes
                    }
                    
                    self._actions.append(action_data)
                    
                    # Update action map
                    if action_id not in self._action_map:
                        self._action_map[action_id] = []
                    self._action_map[action_id].append(action_data)
                    
                    # Add to table
                    self._table_model.addRow([
                        action_data['id'],
                        action_data['method'],
                        action_data['url'],
                        action_data['action_id'],
                        action_data['parameters'][:100] + "..." if len(action_data['parameters']) > 100 else action_data['parameters'],
                        action_data['request_size'],
                        action_data['response_size'],
                        action_data['status'],
                        action_data['timestamp'],
                        action_data['security_notes'],
                        action_data['action_notes']
                    ])
                    
                    # Refresh discovery if visible
                    if self._main_tabbed_pane.getSelectedIndex() == 1:
                        self.refresh_discovery(None)
    
    def _get_timestamp(self, headers):
        # Try to get timestamp from Date header
        for header in headers:
            if header.lower().startswith('date:'):
                date_str = header.split(':', 1)[1].strip()
                try:
                    # Parse HTTP date format
                    from java.text import SimpleDateFormat
                    from java.util import Locale
                    sdf = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US)
                    date = sdf.parse(date_str)
                    return SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(date)
                except:
                    pass
        # Fallback to current time
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _get_request_body(self, messageInfo):
        request = messageInfo.getRequest()
        request_info = self._helpers.analyzeRequest(messageInfo)
        body_offset = request_info.getBodyOffset()
        return self._helpers.bytesToString(request[body_offset:])
    
    def _extract_parameters(self, messageInfo):
        params = {}
        request_info = self._helpers.analyzeRequest(messageInfo)
        
        # Get URL parameters
        for param in request_info.getParameters():
            if param.getType() == 0:  # URL parameter
                params[param.getName()] = param.getValue()
        
        # Get body parameters
        body = self._get_request_body(messageInfo)
        if body:
            # Try JSON
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    params.update(data)
                elif isinstance(data, list) and len(data) > 0:
                    # For arrays, try to extract meaningful data
                    for i, item in enumerate(data[:5]):  # First 5 items
                        if isinstance(item, dict):
                            for k, v in item.items():
                                params[k] = str(v)
                        else:
                            params['arg_' + str(i)] = str(item)
            except:
                # Try form data
                if '=' in body and '&' in body:
                    for pair in body.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            params[key] = value
        
        return params
    
    def _analyze_security(self, messageInfo, action_id, params):
        notes = []
        
        request_info = self._helpers.analyzeRequest(messageInfo)
        headers_str = '\n'.join(request_info.getHeaders())
        
        # Check for authentication
        if 'authorization' not in headers_str.lower() and 'cookie' not in headers_str.lower():
            notes.append("No auth headers")
        
        # Check for potentially dangerous parameters (data access patterns)
        dangerous_params = ['id', 'userId', 'user_id', 'role', 'admin', 'delete', 'update', 'team', 'teamId']
        for param in params:
            if any(danger in param.lower() for danger in dangerous_params):
                notes.append(param)
        
        # Check for direct database IDs being passed (potential IDOR)
        for param, value in params.items():
            if 'id' in param.lower() and str(value).isdigit():
                notes.append("Direct ID: " + param + "=" + str(value))
        
        # Check response for errors that might leak info
        response = self._helpers.bytesToString(messageInfo.getResponse())
        response_lower = response.lower()
        
        # Look for development mode indicators
        if 'development' in response_lower or '__next_data__' in response:
            notes.append("Dev mode indicators")
        
        # Check for error information leakage
        # Look for actual error messages, not just the word "error"
        error_patterns = [
            r'"error"\s*:\s*"[^"]+',  # "error": "some message"
            r'"error"\s*:\s*\{',       # "error": { object }
            r'"error"\s*:\s*\[',       # "error": [ array ]
            r'exception',
            r'stack\s*trace',
            r'stacktrace',
            r'at\s+\w+\.\w+\(',       # Java stack trace pattern
            r'File\s+"[^"]+",\s+line\s+\d+',  # Python stack trace
            r'TypeError:|ReferenceError:|SyntaxError:',  # JS errors
            r'undefined method',       # Ruby errors
            r'Call to undefined function'  # PHP errors
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                notes.append("Error in response")
                break
            
        # Check for SQL/database errors
        if any(db_err in response_lower for db_err in ['sql', 'postgres', 'mysql', 'database error']):
            notes.append("DB error exposed")
        
        # Check for Origin/Host validation (Next.js should do this automatically)
        origin_header = None
        host_header = None
        for header in request_info.getHeaders():
            if header.lower().startswith('origin:'):
                origin_header = header.split(':', 1)[1].strip()
            elif header.lower().startswith('host:'):
                host_header = header.split(':', 1)[1].strip()
        
        if origin_header and host_header:
            # Extract just the host part from origin
            try:
                origin_host = origin_header.replace('https://', '').replace('http://', '').split('/')[0]
                if origin_host != host_header:
                    notes.append("Origin/Host mismatch")
            except:
                pass
        
        # Check if same action ID is used multiple times (might indicate static actions)
        if action_id and action_id in self._action_map and len(self._action_map[action_id]) > 10:
            notes.append("Action reused " + str(len(self._action_map[action_id])) + "x")
        
        # Check for .bind() pattern in body (unencrypted params)
        body = self._get_request_body(messageInfo)
        if body and '.bind(' in body:
            notes.append("Potential .bind() usage")
        
        # Check HTTP method for Server Actions
        if request_info.getMethod() != "POST" and action_id:
            notes.append("Non-POST action")
        
        return '; '.join(notes) if notes else ''
    
    def _analyze_response_fields(self, response_body):
        """Extract JSON field names from response"""
        fields = set()
        
        try:
            # Try to parse as JSON
            data = json.loads(response_body)
            
            def extract_fields(obj, prefix=""):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        field_name = prefix + key if prefix else key
                        fields.add(field_name)
                        # Recursively extract nested fields (one level deep)
                        if isinstance(value, dict) and not prefix:
                            extract_fields(value, key + ".")
                        elif isinstance(value, list) and value and isinstance(value[0], dict) and not prefix:
                            extract_fields(value[0], key + "[].")
                elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                    extract_fields(obj[0], prefix)
            
            extract_fields(data)
        except:
            # If not JSON, try to identify response type
            if response_body.strip().startswith('<!DOCTYPE') or response_body.strip().startswith('<html'):
                fields.add("_html_response")
            elif response_body.strip():
                fields.add("_text_response")
        
        return fields
    
    def apply_filter(self):
        filter_text = self._action_filter.getText().lower()
        
        # Use a row sorter with filter
        from javax.swing import RowFilter
        from javax.swing.table import TableRowSorter
        
        if not hasattr(self, '_row_sorter'):
            self._row_sorter = TableRowSorter(self._table_model)
            self._actions_table.setRowSorter(self._row_sorter)
        
        if filter_text:
            # Create filter that checks multiple columns
            filters = []
            
            # Filter by action ID (column 3)
            try:
                action_filter = RowFilter.regexFilter("(?i)" + filter_text, 3)
                filters.append(action_filter)
            except:
                pass
            
            # Filter by URL (column 2)
            try:
                url_filter = RowFilter.regexFilter("(?i)" + filter_text, 2)
                filters.append(url_filter)
            except:
                pass
            
            # Filter by parameters (column 4)
            try:
                param_filter = RowFilter.regexFilter("(?i)" + filter_text, 4)
                filters.append(param_filter)
            except:
                pass
            
            # Filter by security notes (column 9)
            try:
                security_filter = RowFilter.regexFilter("(?i)" + filter_text, 9)
                filters.append(security_filter)
            except:
                pass
            
            # Combine filters with OR logic
            if filters:
                combined_filter = RowFilter.orFilter(filters)
                self._row_sorter.setRowFilter(combined_filter)
            else:
                self._row_sorter.setRowFilter(None)
        else:
            self._row_sorter.setRowFilter(None)
    
    def find_requests_by_action(self, action_id):
        # Switch to requests tab and filter
        self._main_tabbed_pane.setSelectedIndex(0)
        self._action_filter.setText(action_id)
        # The DocumentListener will automatically trigger the filter
    
    def table_selection_changed(self):
        selected_row = self._actions_table.getSelectedRow()
        if selected_row >= 0:
            # Get the actual model row (in case table is sorted)
            model_row = self._actions_table.convertRowIndexToModel(selected_row)
            action_index = int(self._table_model.getValueAt(model_row, 0)) - 1
            
            if 0 <= action_index < len(self._actions):
                action = self._actions[action_index]
                messageInfo = action['messageInfo']
                self._current_action_id = action['action_id']
                
                # Update request/response viewers
                self._request_viewer.setMessage(messageInfo.getRequest(), True)
                self._response_viewer.setMessage(messageInfo.getResponse(), False)
                
                # Update notes field
                self._notes_area.setText(self._action_notes.get(self._current_action_id, ""))
    
    
    def save_notes(self, event):
        if self._current_action_id:
            notes = self._notes_area.getText()
            self._action_notes[self._current_action_id] = notes
            
            # Update all rows with this action ID
            with self._lock:
                for i in range(self._table_model.getRowCount()):
                    if self._table_model.getValueAt(i, 3) == self._current_action_id:
                        self._table_model.setValueAt(notes, i, 10)
                
                # Update stored actions
                for action in self._actions:
                    if action['action_id'] == self._current_action_id:
                        action['action_notes'] = notes
            
            print("Notes saved for action: " + self._current_action_id)
    
    def clear_table(self, event):
        with self._lock:
            # Clear filter first
            self._action_filter.setText("")
            
            self._table_model.setRowCount(0)
            self._actions = []
            self._action_map = {}
            self._action_notes = {}
            self._request_id = 0
            self._stats = {
                'total_actions': 0,
                'unique_actions': set(),
                'post_actions': 0,
                'get_actions': 0,
                'auth_missing': 0,
                'errors_exposed': 0
            }
            
            # Clear discovery tables
            self._all_actions_model.setRowCount(0)
            self._unused_actions_model.setRowCount(0)
            self._unknown_actions_model.setRowCount(0)
    
    def export_actions(self, event):
        """Export analysis with improved user experience"""
        from javax.swing import JFileChooser, JOptionPane
        from javax.swing.filechooser import FileNameExtensionFilter
        import os
        
        # Show export options dialog
        from javax.swing import JCheckBox, JPanel, JLabel, BoxLayout
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        
        panel.add(JLabel("Select export options:"))
        panel.add(JLabel(" "))
        
        include_executed = JCheckBox("Include executed actions", True)
        include_unused = JCheckBox("Include unused actions (by function name)", True)
        include_security = JCheckBox("Include security findings", True)
        include_full_details = JCheckBox("Include full request/response data", False)
        
        panel.add(include_executed)
        panel.add(include_unused)
        panel.add(include_security)
        panel.add(include_full_details)
        
        result = JOptionPane.showConfirmDialog(
            self._main_panel,
            panel,
            "Export Options",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        )
        
        if result != JOptionPane.OK_OPTION:
            return
        
        # Export all unique action IDs and their usage with security analysis
        export_data = {
            'export_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'export_info': {
                'description': 'Next.js Server Actions Security Analysis',
                'unused_actions_note': 'Unused actions are determined by function name matching, not action ID'
            },
            'statistics': {
                'total_requests': self._stats['total_actions'],
                'unique_actions': len(self._stats['unique_actions']),
                'post_actions': self._stats['post_actions'],
                'get_actions': self._stats['get_actions'],
                'missing_auth': self._stats['auth_missing'],
                'error_responses': self._stats['errors_exposed'],
                'total_discovered_actions': len(self._all_discovered_actions),
                'unused_actions': len(set(self._all_discovered_actions.keys()) - self._stats['unique_actions']),
                'unknown_executed_actions': len(self._stats['unique_actions'] - set(self._all_discovered_actions.keys()))
            },
            'action_summary': {},
            'unused_actions': {},
            'security_findings': {
                'unauthenticated_actions': [],
                'sensitive_param_actions': [],
                'error_leaking_actions': [],
                'frequently_reused_actions': [],
                'documented_actions': []
            }
        }
        
        # Build function name tracking for unused action detection
        executed_function_names = set()
        for action_id in self._stats['unique_actions']:
            if action_id in self._action_names:
                executed_function_names.add(self._action_names[action_id])
        
        # Add unused actions to export (based on function name, not action ID)
        if include_unused.isSelected():
            for action_id, info in self._all_discovered_actions.items():
                function_name = info['function_name']
                # Action is unused if its function name has never been executed
                if function_name not in executed_function_names:
                    export_data['unused_actions'][action_id] = {
                        'function_name': function_name,
                        'chunk_file': info['chunk_file'],
                        'discovery_time': info['first_seen'],
                        'status': 'Never Executed'
                    }
        
        # Add executed actions if selected
        if include_executed.isSelected():
            for action_id, usages in self._action_map.items():
                action_summary = {
                    'function_name': self._action_names.get(action_id, "Unknown"),
                    'count': len(usages),
                    'endpoints': list(set(u['url'] for u in usages)),
                    'methods': list(set(u['method'] for u in usages)),
                    'status_codes': list(set(u['status'] for u in usages)),
                    'parameters': list(set(p for u in usages for p in json.loads(u['parameters']).keys())),
                    'security_notes': list(set(u['security_notes'] for u in usages if u['security_notes'])),
                    'user_notes': self._action_notes.get(action_id, "")
                }
                
                # Add full details if requested
                if include_full_details.isSelected():
                    action_summary['requests'] = []
                    for usage in usages[:5]:  # Limit to first 5 to avoid huge exports
                        action_summary['requests'].append({
                            'timestamp': usage['timestamp'],
                            'url': usage['url'],
                            'method': usage['method'],
                            'status': usage['status'],
                            'parameters': json.loads(usage['parameters'])
                        })
                
                export_data['action_summary'][action_id] = action_summary
            
        # Process security findings if selected
        if include_security.isSelected() and include_executed.isSelected():
            for action_id, usages in self._action_map.items():
                # Add to documented actions if notes exist
                if action_id in self._action_notes and self._action_notes[action_id]:
                    export_data['security_findings']['documented_actions'].append({
                        'action_id': action_id,
                        'function_name': self._action_names.get(action_id, "Unknown"),
                        'notes': self._action_notes[action_id],
                        'usage_count': len(usages)
                    })
                
                # Categorize security findings
                for usage in usages:
                    if "No auth headers" in usage['security_notes']:
                        export_data['security_findings']['unauthenticated_actions'].append({
                            'action_id': action_id,
                            'function_name': self._action_names.get(action_id, "Unknown"),
                            'url': usage['url'],
                            'params': usage['parameters']
                        })
                    
                    # Check for sensitive params by looking for param names in notes
                    security_notes_list = usage['security_notes'].split('; ') if usage['security_notes'] else []
                    dangerous_params = ['id', 'userId', 'user_id', 'role', 'admin', 'delete', 'update', 'team', 'teamId']
                    for note in security_notes_list:
                        if any(danger in note.lower() for danger in dangerous_params) and ':' not in note:
                            export_data['security_findings']['sensitive_param_actions'].append({
                                'action_id': action_id,
                                'function_name': self._action_names.get(action_id, "Unknown"),
                                'url': usage['url'],
                                'param': note,
                                'all_params': usage['parameters']
                            })
                            
                    if "Error in response" in usage['security_notes'] or "DB error exposed" in usage['security_notes']:
                        export_data['security_findings']['error_leaking_actions'].append({
                            'action_id': action_id,
                            'function_name': self._action_names.get(action_id, "Unknown"),
                            'url': usage['url'],
                            'status': usage['status']
                        })
                
                if len(usages) > 10:
                    export_data['security_findings']['frequently_reused_actions'].append({
                        'action_id': action_id,
                        'function_name': self._action_names.get(action_id, "Unknown"),
                        'usage_count': len(usages),
                        'endpoints': list(set(u['url'] for u in usages))
                    })
        
        # Deduplicate findings
        if include_security.isSelected():
            for key in export_data['security_findings']:
                if key != 'documented_actions':
                    seen = set()
                    unique_items = []
                    for item in export_data['security_findings'][key]:
                        item_key = json.dumps(item, sort_keys=True)
                        if item_key not in seen:
                            seen.add(item_key)
                            unique_items.append(item)
                    export_data['security_findings'][key] = unique_items
        
        # Clean up empty sections if not selected
        if not include_security.isSelected():
            del export_data['security_findings']
        if not include_executed.isSelected():
            del export_data['action_summary']
        if not include_unused.isSelected():
            del export_data['unused_actions']
        
        # Update statistics based on function names
        export_data['statistics']['unused_actions_by_name'] = len(set(
            info['function_name'] for info in self._all_discovered_actions.values()
            if info['function_name'] not in executed_function_names
        ))
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Next.js Actions Analysis")
        from java.io import File
        chooser.setSelectedFile(File("nextjs-actions-analysis.json"))
        filter = FileNameExtensionFilter("JSON files", ["json"])
        chooser.setFileFilter(filter)
        
        if chooser.showSaveDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith('.json'):
                file_path += '.json'
            
            try:
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Export saved successfully to:\n" + file_path,
                    "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE
                )
                print("Export saved to: " + file_path)
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Failed to save export:\n" + str(e),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
                )
                print("Export failed: " + str(e))
    
    def send_to_repeater(self):
        selected_row = self._actions_table.getSelectedRow()
        if selected_row >= 0:
            model_row = self._actions_table.convertRowIndexToModel(selected_row)
            action_index = int(self._table_model.getValueAt(model_row, 0)) - 1
            
            if 0 <= action_index < len(self._actions):
                action = self._actions[action_index]
                messageInfo = action['messageInfo']
                self._callbacks.sendToRepeater(
                    messageInfo.getHttpService().getHost(),
                    messageInfo.getHttpService().getPort(),
                    messageInfo.getHttpService().getProtocol() == "https",
                    messageInfo.getRequest(),
                    "Next.js Action: " + action['action_id'][:8]
                )
    
    def send_to_intruder(self):
        selected_row = self._actions_table.getSelectedRow()
        if selected_row >= 0:
            model_row = self._actions_table.convertRowIndexToModel(selected_row)
            action_index = int(self._table_model.getValueAt(model_row, 0)) - 1
            
            if 0 <= action_index < len(self._actions):
                action = self._actions[action_index]
                messageInfo = action['messageInfo']
                self._callbacks.sendToIntruder(
                    messageInfo.getHttpService().getHost(),
                    messageInfo.getHttpService().getPort(),
                    messageInfo.getHttpService().getProtocol() == "https",
                    messageInfo.getRequest()
                )
    
    def send_to_intruder_with_positions(self):
        selected_row = self._actions_table.getSelectedRow()
        if selected_row >= 0:
            model_row = self._actions_table.convertRowIndexToModel(selected_row)
            action_index = int(self._table_model.getValueAt(model_row, 0)) - 1
            
            if 0 <= action_index < len(self._actions):
                action = self._actions[action_index]
                messageInfo = action['messageInfo']
                request = self._helpers.bytesToString(messageInfo.getRequest())
                
                # Add payload positions for parameters
                params = json.loads(action['parameters'])
                modified_request = request
                
                # Use unicode for the section sign character
                marker = u'\u00a7'
                
                for param_name, param_value in params.items():
                    # Add Intruder position markers around parameter values
                    # Look for the parameter in JSON body
                    json_pattern = '"%s"\\s*:\\s*"([^"]*)"' % re.escape(param_name)
                    json_match = re.search(json_pattern, modified_request)
                    if json_match:
                        original = json_match.group(0)
                        replacement = original.replace(json_match.group(1), marker + json_match.group(1) + marker)
                        modified_request = modified_request.replace(original, replacement)
                    
                    # Look for form-encoded parameters
                    form_pattern = '%s=([^&]*)' % re.escape(param_name)
                    form_match = re.search(form_pattern, modified_request)
                    if form_match:
                        original = form_match.group(0)
                        replacement = param_name + "=" + marker + form_match.group(1) + marker
                        modified_request = modified_request.replace(original, replacement)
                
                # Send to Intruder with positions marked
                self._callbacks.sendToIntruder(
                    messageInfo.getHttpService().getHost(),
                    messageInfo.getHttpService().getPort(),
                    messageInfo.getHttpService().getProtocol() == "https",
                    self._helpers.stringToBytes(modified_request)
                )
                print("Sent to Intruder with %d parameter positions marked" % len(params))
    
    def getHttpService(self):
        return self._current_message.getHttpService() if hasattr(self, '_current_message') else None
    
    def getRequest(self):
        return self._current_message.getRequest() if hasattr(self, '_current_message') else None
    
    def getResponse(self):
        return self._current_message.getResponse() if hasattr(self, '_current_message') else None
    
    def find_function_in_responses(self, action_id, function_name):
        """Find and navigate to the response containing the function definition"""
        print("Searching for function: " + function_name + " (Action ID: " + action_id + ")")
        
        # First check if we have the chunk stored from discovery
        if action_id in self._all_discovered_actions:
            action_info = self._all_discovered_actions[action_id]
            if 'message_info' in action_info:
                # Navigate to the chunk response
                message = action_info['message_info']
                self._callbacks.sendToRepeater(
                    message.getHttpService().getHost(),
                    message.getHttpService().getPort(),
                    message.getHttpService().getProtocol() == "https",
                    message.getRequest(),
                    "Chunk: " + function_name
                )
                print("Opened chunk containing function: " + function_name)
                return
        
        # If not found in discovery, search through all chunk responses
        for chunk_data in self._chunk_responses:
            if function_name in chunk_data['body']:
                message = chunk_data['message']
                self._callbacks.sendToRepeater(
                    message.getHttpService().getHost(),
                    message.getHttpService().getPort(),
                    message.getHttpService().getProtocol() == "https",
                    message.getRequest(),
                    "Chunk: " + function_name
                )
                print("Found function in chunk: " + chunk_data['url'])
                return
        
        print("Function not found in stored chunk responses")
    
    def create_repeater_request_for_action(self, action_id, function_name):
        """Create a Repeater request with the unused action ID"""
        print("Creating Repeater request for action: " + function_name + " (" + action_id + ")")
        
        # Find a template request - prefer one that already has a Next-Action header
        template_request = None
        template_service = None
        
        # First, try to find an existing action request as template
        if self._actions:
            # Use the most recent action request
            recent_action = self._actions[-1]
            template_request = recent_action['messageInfo'].getRequest()
            template_service = recent_action['messageInfo'].getHttpService()
        else:
            # Fall back to any POST request from proxy history
            proxy_history = self._callbacks.getProxyHistory()
            for message in reversed(proxy_history[-100:]):  # Check last 100 requests
                if message.getRequest():
                    request_info = self._helpers.analyzeRequest(message)
                    if request_info.getMethod() == "POST":
                        headers_str = '\n'.join(request_info.getHeaders())
                        # Prefer requests to the same app
                        if '/_next/' in str(request_info.getUrl()) or 'next-action' in headers_str.lower():
                            template_request = message.getRequest()
                            template_service = message.getHttpService()
                            break
        
        if not template_request:
            print("No suitable template request found. Please make at least one server action request first.")
            return
        
        # Modify the request with the new action ID
        request_str = self._helpers.bytesToString(template_request)
        request_info = self._helpers.analyzeRequest(template_service, template_request)
        headers = request_info.getHeaders()
        body_offset = request_info.getBodyOffset()
        body = request_str[body_offset:]
        
        # Update or add Next-Action header
        new_headers = []
        action_header_found = False
        for header in headers:
            if header.lower().startswith('next-action:'):
                new_headers.append('Next-Action: ' + action_id)
                action_header_found = True
            else:
                new_headers.append(header)
        
        if not action_header_found:
            # Add Next-Action header after Host header
            for i, header in enumerate(new_headers):
                if header.lower().startswith('host:'):
                    new_headers.insert(i + 1, 'Next-Action: ' + action_id)
                    break
        
        # Build new request
        new_request = '\r\n'.join(new_headers) + '\r\n\r\n' + body
        
        # Send to Repeater
        self._callbacks.sendToRepeater(
            template_service.getHost(),
            template_service.getPort(),
            template_service.getProtocol() == "https",
            self._helpers.stringToBytes(new_request),
            "Test: " + function_name
        )
        
        print("Created Repeater request for testing: " + function_name)

class TableMouseListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender
        
    def mousePressed(self, event):
        if event.isPopupTrigger():
            self.showPopup(event)
    
    def mouseReleased(self, event):
        if event.isPopupTrigger():
            self.showPopup(event)
    
    def showPopup(self, event):
        from javax.swing import JPopupMenu, JMenuItem
        
        # Get the row that was right-clicked
        row = self.extender._actions_table.rowAtPoint(event.getPoint())
        if row >= 0:
            self.extender._actions_table.setRowSelectionInterval(row, row)
            
            # Create popup menu
            popup = JPopupMenu()
            
            send_repeater = JMenuItem("Send to Repeater")
            send_repeater.addActionListener(lambda e: self.extender.send_to_repeater())
            popup.add(send_repeater)
            
            send_intruder = JMenuItem("Send to Intruder")
            send_intruder.addActionListener(lambda e: self.extender.send_to_intruder())
            popup.add(send_intruder)
            
            send_intruder_fuzz = JMenuItem("Send to Intruder (Auto-mark Parameters)")
            send_intruder_fuzz.addActionListener(lambda e: self.extender.send_to_intruder_with_positions())
            popup.add(send_intruder_fuzz)
            
            popup.addSeparator()
            
            copy_action_id = JMenuItem("Copy Action ID")
            copy_action_id.addActionListener(lambda e: self.copy_action_id(row))
            popup.add(copy_action_id)
            
            popup.addSeparator()
            
            lookup_action = JMenuItem("Lookup Server Action")
            lookup_action.addActionListener(lambda e: self.lookup_server_action(row))
            popup.add(lookup_action)
            
            popup.show(event.getComponent(), event.getX(), event.getY())
    
    def copy_action_id(self, row):
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        
        model_row = self.extender._actions_table.convertRowIndexToModel(row)
        action_id = self.extender._table_model.getValueAt(model_row, 3)
        
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(action_id), None)
        print("Copied action ID: " + action_id)
    
    def lookup_server_action(self, row):
        """Lookup the server action name and add it to notes"""
        model_row = self.extender._actions_table.convertRowIndexToModel(row)
        action_id = self.extender._table_model.getValueAt(model_row, 3)
        
        if action_id in self.extender._action_names:
            function_name = self.extender._action_names[action_id]
            
            # Get current notes
            current_notes = self.extender._action_notes.get(action_id, "")
            
            # Add function name if not already in notes
            function_text = "Function: " + function_name
            if function_text not in current_notes:
                if current_notes:
                    new_notes = function_text + "\n" + current_notes
                else:
                    new_notes = function_text
                
                # Save the updated notes
                self.extender._action_notes[action_id] = new_notes
                
                # Update the table
                with self.extender._lock:
                    for i in range(self.extender._table_model.getRowCount()):
                        if self.extender._table_model.getValueAt(i, 3) == action_id:
                            self.extender._table_model.setValueAt(new_notes, i, 10)
                    
                    # Update the actions list
                    for action in self.extender._actions:
                        if action['action_id'] == action_id:
                            action['action_notes'] = new_notes
                
                # Update notes area if this action is currently selected
                if self.extender._current_action_id == action_id:
                    self.extender._notes_area.setText(new_notes)
                
                print("Found and added server action: " + function_name + " for action ID: " + action_id)
            else:
                print("Server action already in notes: " + function_name)
        else:
            print("No server action name found for action ID: " + action_id)
            print("Try running 'Extract Action Names' first to scan chunk files")

class DiscoveryTableMouseListener(MouseAdapter):
    def __init__(self, extender, table):
        self.extender = extender
        self.table = table
        
    def mousePressed(self, event):
        if event.isPopupTrigger():
            self.showPopup(event)
    
    def mouseReleased(self, event):
        if event.isPopupTrigger():
            self.showPopup(event)
    
    def showPopup(self, event):
        from javax.swing import JPopupMenu, JMenuItem
        
        row = self.table.rowAtPoint(event.getPoint())
        if row >= 0:
            self.table.setRowSelectionInterval(row, row)
            model_row = self.table.convertRowIndexToModel(row)
            
            # Get action data from table
            action_id = str(self.table.getModel().getValueAt(model_row, 0))
            function_name = str(self.table.getModel().getValueAt(model_row, 1))
            status = str(self.table.getModel().getValueAt(model_row, 2))
            
            popup = JPopupMenu()
            
            # Find function in responses
            find_function = JMenuItem("Find Function in Responses")
            find_function.addActionListener(lambda e: self.extender.find_function_in_responses(action_id, function_name))
            popup.add(find_function)
            
            popup.addSeparator()
            
            # Create request in Repeater
            create_request = JMenuItem("Create Request in Repeater")
            create_request.addActionListener(lambda e: self.extender.create_repeater_request_for_action(action_id, function_name))
            popup.add(create_request)
            
            popup.addSeparator()
            
            # Copy action ID
            copy_action_id = JMenuItem("Copy Action ID")
            copy_action_id.addActionListener(lambda e: self.copy_action_id(action_id))
            popup.add(copy_action_id)
            
            # Copy function name
            copy_function = JMenuItem("Copy Function Name")
            copy_function.addActionListener(lambda e: self.copy_function_name(function_name))
            popup.add(copy_function)
            
            # Show action info in summary
            if action_id in self.extender._action_map and self.extender._action_map[action_id]:
                popup.addSeparator()
                view_requests = JMenuItem("View All Requests for this Action")
                view_requests.addActionListener(lambda e: self.extender.find_requests_by_action(action_id))
                popup.add(view_requests)
            
            popup.show(event.getComponent(), event.getX(), event.getY())
    
    def copy_action_id(self, action_id):
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(action_id), None)
        print("Copied action ID: " + action_id)
    
    def copy_function_name(self, function_name):
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(function_name), None)
        print("Copied function name: " + function_name)