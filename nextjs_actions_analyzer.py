# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController, IContextMenuFactory, IExtensionStateListener
from javax.swing import JPanel, JTable, JScrollPane, JSplitPane, JButton, JTextField, JLabel, JMenuItem, JTextArea, SwingUtilities, Timer
from javax.swing.table import DefaultTableModel, TableRowSorter, AbstractTableModel
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import MouseAdapter
import java.lang
import java.io
import json
from datetime import datetime
import re
from threading import Lock, Thread
import time

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController, IContextMenuFactory, IExtensionStateListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Next.js Server Actions Analyzer")
        
        # Thread safety
        self._lock = Lock()
        
        # Track background threads for cleanup
        self._background_threads = []
        self._shutdown = False
        
        # Create UI
        self._main_panel = JPanel(BorderLayout())
        
        # Get Burp Suite main frame for proper dialog parenting
        self._burp_frame = None
        try:
            # Get the Burp frame through the callbacks
            for frame in java.awt.Frame.getFrames():
                if "Burp Suite" in frame.getTitle():
                    self._burp_frame = frame
                    break
        except:
            pass
        
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
        
        # Unused actions table
        self._unused_actions_model = DiscoveryTableModel()
        self._unused_actions_table = JTable(self._unused_actions_model)
        self._unused_actions_table.setAutoCreateRowSorter(True)
        
        # Unknown actions table (executed but not in chunks)
        self._unknown_actions_model = DiscoveryTableModel()
        self._unknown_actions_table = JTable(self._unknown_actions_model)
        self._unknown_actions_table.setAutoCreateRowSorter(True)
        
        # Add mouse listeners for context menus
        self._all_actions_table.addMouseListener(DiscoveryTableMouseListener(self, self._all_actions_table))
        self._unused_actions_table.addMouseListener(DiscoveryTableMouseListener(self, self._unused_actions_table))
        self._unknown_actions_table.addMouseListener(DiscoveryTableMouseListener(self, self._unknown_actions_table))
        
        discovery_tabs.addTab("All Discovered Actions", JScrollPane(self._all_actions_table))
        discovery_tabs.addTab("Unused Actions (Never Executed)", JScrollPane(self._unused_actions_table))
        discovery_tabs.addTab("Unknown Actions (No Source Found)", JScrollPane(self._unknown_actions_table))
        
        self._discovery_panel.add(discovery_tabs, BorderLayout.CENTER)
        
        # Add tabs to main panel
        self._main_tabbed_pane.addTab("All Requests", self._requests_panel)
        self._main_tabbed_pane.addTab("Action Discovery", self._discovery_panel)
        
        self._main_panel.add(self._main_tabbed_pane, BorderLayout.CENTER)
        
        # Storage for Server Actions
        self._actions = []
        self._action_notes = {}  # Stores notes per action ID
        self._action_names = {}  # Stores function names for action IDs
        self._all_discovered_actions = {}  # All actions found in chunks
        self._chunk_responses = []  # Store chunk responses for searching
        self._action_map = {}  # Map action IDs to their usage details for export
        self._current_action_id = None  # Track currently selected action for notes
        
        # Statistics
        self._stats = {
            'total_actions': 0,
            'unique_actions': set(),
            'potential_issues': []
        }
        
        # Register extension
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        # Register extension state listener for cleanup
        callbacks.registerExtensionStateListener(self)
        
        # Table selection listener
        from javax.swing.event import ListSelectionListener
        class SelectionListener(ListSelectionListener):
            def __init__(self, extender):
                self.extender = extender
            def valueChanged(self, e):
                if not e.getValueIsAdjusting():
                    self.extender.table_selection_changed()
        
        self._actions_table.getSelectionModel().addListSelectionListener(SelectionListener(self))
        
        print("Next.js Server Actions Analyzer loaded!")
        print("Usage:")
        print("1. Click 'Scan Proxy History' to analyze past requests")
        print("2. Browse the application - new Server Actions will be captured automatically")
        print("3. Click 'Extract Action Names' to get function names from JavaScript chunks")
        print("4. Click 'Find Unused Actions' to discover all defined actions")
        print("5. Right-click on any row for additional options")
    
    def extensionUnloaded(self):
        """Clean up resources when extension is unloaded"""
        print("Unloading Next.js Server Actions Analyzer...")
        
        # Set shutdown flag to stop background threads
        self._shutdown = True
        
        # Wait for background threads to complete
        for thread in self._background_threads:
            try:
                thread.join(timeout=2.0)
            except:
                pass
        
        # Clear data structures
        self._actions = []
        self._action_notes.clear()
        self._action_names.clear()
        self._all_discovered_actions.clear()
        self._chunk_responses = []
        
        print("Next.js Server Actions Analyzer unloaded successfully")
    
    def getTabCaption(self):
        return "Next.js Actions"
    
    def getUiComponent(self):
        return self._main_panel
    
    def createMenuItems(self, invocation):
        menu_items = []
        
        # Get selected messages
        messages = invocation.getSelectedMessages()
        
        if messages and len(messages) > 0:
            menu_item = JMenuItem("Analyze for Next.js Actions", actionPerformed=lambda e: self.analyze_selected_items(invocation))
            menu_items.append(menu_item)
            
            lookup_item = JMenuItem("Lookup Server Action Name", actionPerformed=lambda e: self.lookup_action_for_request(invocation))
            menu_items.append(lookup_item)
        
        # Add context menu for table rows
        if invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            if hasattr(self, '_current_message') and self._current_message:
                menu_items.append(JMenuItem("Send to Repeater", actionPerformed=lambda e: self.send_to_repeater()))
                menu_items.append(JMenuItem("Send to Intruder", actionPerformed=lambda e: self.send_to_intruder()))
                menu_items.append(JMenuItem("Send to Intruder (Fuzz Parameters)", actionPerformed=lambda e: self.send_to_intruder_with_positions()))
        
        return menu_items if menu_items else None
    
    def analyze_selected_items(self, invocation):
        for message in invocation.getSelectedMessages():
            self.processHttpMessage(0, False, message)
    
    def lookup_action_for_request(self, invocation):
        """Lookup server action name for selected request"""
        messages = invocation.getSelectedMessages()
        if messages:
            for message in messages:
                request_info = self._helpers.analyzeRequest(message)
                headers = request_info.getHeaders()
                
                # Look for Next-Action header
                action_id = None
                for header in headers:
                    if header.lower().startswith("next-action:"):
                        action_id = header.split(":", 1)[1].strip()
                        break
                
                if action_id:
                    # Check if we have a name for this action
                    if action_id in self._action_names:
                        function_name = self._action_names[action_id]
                        print("\n=== Server Action Found ===")
                        print("Action ID: " + action_id)
                        print("Function Name: " + function_name)
                        
                        # Find in discovered actions for more info
                        if action_id in self._all_discovered_actions:
                            info = self._all_discovered_actions[action_id]
                            print("Chunk File: " + info.get('chunk_file', 'Unknown'))
                            print("First Seen: " + info.get('first_seen', 'Unknown'))
                        
                        # Show execution count
                        exec_count = sum(1 for a in self._actions if a['action_id'] == action_id)
                        print("Executed Count: " + str(exec_count))
                    else:
                        print("Server action ID found: " + action_id)
                        print("Function name not found - try 'Extract Action Names' or 'Find Unused Actions'")
                else:
                    # Try to find in request body
                    body = self._get_request_body(message)
                    if body and len(body) > 0:
                        try:
                            data = json.loads(body)
                            if isinstance(data, list) and len(data) > 0:
                                action_id = data[0]
                                if action_id in self._action_names:
                                    print("Server action found in body: " + action_id + " => " + self._action_names[action_id])
                                else:
                                    print("Server action ID in body: " + action_id)
                        except:
                            pass
                
                if action_id:
                    print("No server action name found for action ID: " + action_id)
                    print("Try running 'Extract Action Names' first to scan chunk files")
                else:
                    print("No Next.js action ID found in request")
    
    def scan_proxy_history_threaded(self):
        """Background thread function for scanning proxy history"""
        try:
            proxy_history = self._callbacks.getProxyHistory()
            count = 0
            total = len(proxy_history) if hasattr(proxy_history, '__len__') else 0
            
            for message in proxy_history:
                if self._shutdown:
                    break
                if message.getResponse():
                    self.processHttpMessage(0, False, message)
                    count += 1
                    
                    # Update UI periodically with progress
                    if count % 50 == 0:
                        status_text = "Scanning proxy history... (" + str(count) + " requests processed)"
                        SwingUtilities.invokeLater(lambda text=status_text: self._discovery_status.setText(text))
            
            # Final status update
            final_status = "Scanned " + str(count) + " requests"
            SwingUtilities.invokeLater(lambda text=final_status: self._discovery_status.setText(text))
            
            print("Scanned " + str(count) + " requests from proxy history")
            
            # Auto-update action discovery after scanning
            if not self._shutdown:
                print("Auto-updating action discovery...")
                SwingUtilities.invokeLater(lambda: self.find_all_actions(None))
        except Exception as e:
            print("Error in scan_proxy_history_threaded: " + str(e))
            SwingUtilities.invokeLater(lambda: self._discovery_status.setText("Error during scan"))
    
    def scan_proxy_history(self, event):
        """Start background thread to scan proxy history"""
        # Update UI to show scanning started with visual indicator
        self._discovery_status.setText("Scanning proxy history... ⏳")
        
        # Disable the button to prevent multiple scans
        if event and hasattr(event.getSource(), 'setEnabled'):
            button = event.getSource()
            button.setEnabled(False)
            # Re-enable after scan completes
            def re_enable():
                button.setEnabled(True)
            # Schedule re-enable after a delay
            timer = Timer(3000, lambda e: re_enable())
            timer.setRepeats(False)
            timer.start()
        
        # Start background thread
        thread = Thread(target=self.scan_proxy_history_threaded)
        thread.daemon = True
        self._background_threads.append(thread)
        thread.start()
    
    def find_all_actions_threaded(self):
        """Background thread function for finding all actions"""
        try:
            print("\n=== Scanning for ALL Next.js Server Actions ===")
            SwingUtilities.invokeLater(lambda: self._discovery_status.setText("Scanning chunks..."))
            
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
                if self._shutdown:
                    break
                    
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
            
            if self._shutdown:
                return
                
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
            SwingUtilities.invokeLater(lambda: self._discovery_status.setText(status))
            
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
            SwingUtilities.invokeLater(lambda: self.refresh_discovery(None))
                        
        except Exception as e:
            print("Error in find_all_actions_threaded: " + str(e))
    
    def find_all_actions(self, event):
        """Start background thread to find all actions"""
        # Start background thread
        thread = Thread(target=self.find_all_actions_threaded)
        thread.daemon = True
        self._background_threads.append(thread)
        thread.start()
    
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
        
        # Populate all actions table
        for action_id, info in self._all_discovered_actions.items():
            exec_count = len(self._action_map.get(action_id, []))
            status = "Executed" if action_id in executed_actions else "Unused"
            
            # Check if this function name has been executed under a different ID
            func_name = info['function_name']
            func_executed = False
            if func_name in function_name_map:
                for other_id in function_name_map[func_name]:
                    if other_id in executed_actions:
                        func_executed = True
                        break
            
            if func_executed and action_id not in executed_actions:
                status = "Unused (Function executed with different ID)"
            
            notes = self._action_notes.get(action_id, "")
            
            self._all_actions_model.addRow([
                action_id,
                info['function_name'],
                status,
                info['chunk_file'],
                java.lang.Integer(exec_count),
                notes
            ])
            
            # Add to unused table if never executed
            if action_id not in executed_actions and not func_executed:
                self._unused_actions_model.addRow([
                    action_id,
                    info['function_name'],
                    "Never Executed",
                    info['chunk_file'],
                    java.lang.Integer(0),
                    notes
                ])
        
        # Populate unknown actions table (executed but not found in chunks)
        for action_id in executed_actions:
            if action_id not in self._all_discovered_actions:
                exec_count = len(self._action_map.get(action_id, []))
                notes = self._action_notes.get(action_id, "")
                
                self._unknown_actions_model.addRow([
                    action_id,
                    "Unknown",
                    "Executed (No source found)",
                    "Not found",
                    java.lang.Integer(exec_count),
                    notes
                ])
        
        print("Discovery view refreshed")
        
        # Print summary by function name
        print("\n=== Function-based Analysis ===")
        for func_name, action_ids in sorted(function_name_map.items()):
            executed_ids = [aid for aid in action_ids if aid in executed_actions]
            unused_ids = [aid for aid in action_ids if aid not in executed_actions]
            
            if unused_ids and executed_ids:
                print("Function '" + func_name + "': " + str(len(executed_ids)) + " executed, " + str(len(unused_ids)) + " unused IDs")
            elif unused_ids:
                print("Function '" + func_name + "': NEVER EXECUTED (" + str(len(unused_ids)) + " IDs)")
    
    def extract_action_names_threaded(self):
        """Background thread function for extracting action names"""
        try:
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
                if self._shutdown:
                    break
                    
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
                                print("  ..." + sample)
                            
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
                                            
                                            print("    " + hash_part + "... => " + name_part)
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
                
        except Exception as e:
            print("Error in extract_action_names_threaded: " + str(e))
    
    def extract_action_names(self, event):
        """Start background thread to extract action names"""
        # Update UI
        self._discovery_status.setText("Extracting action names...")
        
        # Start background thread
        thread = Thread(target=self.extract_action_names_threaded)
        thread.daemon = True
        self._background_threads.append(thread)
        thread.start()
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest and messageInfo.getResponse():
            request_info = self._helpers.analyzeRequest(messageInfo)
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            
            # Check if this is a Next.js Server Action
            headers = request_info.getHeaders()
            action_id = None
            
            for header in headers:
                if header.lower().startswith("next-action:"):
                    action_id = header.split(":", 1)[1].strip()
                    break
            
            if action_id:
                # Extract request details
                url = request_info.getUrl()
                method = headers[0].split(" ")[0] if headers else "GET"
                params = self._extract_parameters(messageInfo)
                req_size = len(messageInfo.getRequest())
                res_size = len(messageInfo.getResponse())
                status_code = response_info.getStatusCode()
                timestamp = self._get_timestamp(headers)
                
                # Security analysis
                security_notes = self._analyze_security(messageInfo, action_id, params)
                
                # Get or create action notes
                action_notes = self._action_notes.get(action_id, "")
                
                # Add function name if known
                if action_id in self._action_names:
                    function_name = self._action_names[action_id]
                    if function_name not in action_notes:
                        action_notes = "Function: " + function_name + "\n" + action_notes
                        self._action_notes[action_id] = action_notes
                
                # Create action entry
                action = {
                    'id': len(self._actions) + 1,
                    'method': method,
                    'url': str(url),
                    'action_id': action_id,
                    'params': params,
                    'req_size': req_size,
                    'res_size': res_size,
                    'status': status_code,
                    'timestamp': timestamp,
                    'security_notes': security_notes,
                    'action_notes': action_notes,
                    'messageInfo': messageInfo
                }
                
                # Thread-safe addition
                with self._lock:
                    self._actions.append(action)
                    
                    # Update statistics
                    self._stats['total_actions'] += 1
                    self._stats['unique_actions'].add(action_id)
                    
                    # Update action map for tracking usage
                    if action_id not in self._action_map:
                        self._action_map[action_id] = []
                    
                    # Create usage data for export
                    action_data = {
                        'timestamp': timestamp,
                        'url': str(url),
                        'method': method,
                        'status': status_code,
                        'parameters': params,  # Store raw body string
                        'security_notes': security_notes
                    }
                    self._action_map[action_id].append(action_data)
                    
                    # Add to table  
                    params_str = params[:100] + "..." if len(params) > 100 else params
                    self._table_model.addRow([
                        action['id'],
                        action['method'],
                        action['url'],
                        action['action_id'] if len(action['action_id']) > 20 else action['action_id'],
                        params_str,
                        str(req_size),
                        str(res_size),
                        str(status_code),
                        timestamp,
                        security_notes,
                        action_notes
                    ])
                
                # Alert on security issues
                if security_notes and "CRITICAL" in security_notes:
                    print("⚠️ Security Issue Found in Action: " + action_id)
                    print("  " + security_notes)
    
    def _get_timestamp(self, headers):
        """Extract timestamp from headers or use current time"""
        for header in headers:
            if header.lower().startswith("date:"):
                return header.split(":", 1)[1].strip()
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _get_request_body(self, messageInfo):
        request = messageInfo.getRequest()
        request_info = self._helpers.analyzeRequest(messageInfo)
        body_offset = request_info.getBodyOffset()
        return self._helpers.bytesToString(request[body_offset:])
    
    def _extract_parameters(self, messageInfo):
        """Extract parameters from Server Action request"""
        # Just return the raw body - simple and clear
        body = self._get_request_body(messageInfo)
        return body if body else ""
    
    def _analyze_security(self, messageInfo, action_id, params):
        """Analyze for potential security issues"""
        notes = []
        
        request_info = self._helpers.analyzeRequest(messageInfo)
        headers_str = '\n'.join(request_info.getHeaders())
        
        # Check for authentication
        if 'authorization' not in headers_str.lower() and 'cookie' not in headers_str.lower():
            notes.append("No auth headers")
        
        # Check for potentially dangerous parameters (data access patterns)
        dangerous_params = ['id', 'userId', 'user_id', 'role', 'admin', 'delete', 'update', 'team', 'teamId']
        
        # Check if any dangerous params appear in the body string
        if isinstance(params, str):
            params_lower = params.lower()
            for danger in dangerous_params:
                if danger.lower() in params_lower:
                    notes.append("Contains: " + danger)
        
        # Check for direct database IDs being passed (potential IDOR)
        body = self._get_request_body(messageInfo)
        if body:
            try:
                data = json.loads(body)
                if isinstance(data, list) and len(data) > 1:
                    for param_data in data[1:]:
                        if isinstance(param_data, dict):
                            for key, value in param_data.items():
                                if 'id' in key.lower() and str(value).isdigit():
                                    notes.append("Direct ID: " + key + "=" + str(value))
            except:
                pass
        
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
        if any(db_err in response_lower for db_err in ['mssql', 'postgres', 'mysql', 'database error']):
            notes.append("DB mention")
        
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
        if body and '.bind(' in body:
            notes.append("Potential .bind() usage")
        
        # Check HTTP method for Server Actions
        if request_info.getMethod() != "POST" and action_id:
            notes.append("Non-POST action")
        
        return '; '.join(notes) if notes else ''
    
    def _analyze_response_fields(self, response_body):
        """Extract field names from JSON response"""
        fields = set()
        try:
            data = json.loads(response_body)
            
            def extract_fields(obj, prefix=""):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        fields.add(prefix + key)
                        if isinstance(value, (dict, list)):
                            extract_fields(value, prefix + key + ".")
                elif isinstance(obj, list):
                    for item in obj[:10]:  # Limit to first 10 items
                        extract_fields(item, prefix)
            
            extract_fields(data)
        except:
            pass
        
        return fields
    
    def apply_filter(self):
        """Apply filter to the table"""
        filter_text = self._action_filter.getText().lower()
        
        if not filter_text:
            # Show all rows
            sorter = self._actions_table.getRowSorter()
            if sorter:
                sorter.setRowFilter(None)
        else:
            # Create filter
            from javax.swing import RowFilter
            
            # Create a filter that checks multiple columns
            class MultiColumnFilter(RowFilter):
                def include(self, entry):
                    # Check URL (column 2), Action ID (column 3), Parameters (column 4), 
                    # Security Notes (column 9), and Action Notes (column 10)
                    for col in [2, 3, 4, 9, 10]:
                        value = entry.getStringValue(col)
                        if value and filter_text in value.lower():
                            return True
                    return False
            
            sorter = self._actions_table.getRowSorter()
            if sorter:
                sorter.setRowFilter(MultiColumnFilter())
    
    def find_requests_by_action(self, action_id):
        """Find all requests with a specific action ID"""
        return [action for action in self._actions if action['action_id'] == action_id]
    
    def table_selection_changed(self):
        selected_row = self._actions_table.getSelectedRow()
        if selected_row >= 0:
            # Convert view row to model row
            model_row = self._actions_table.convertRowIndexToModel(selected_row)
            
            # Get the action ID from the model
            action_index = int(self._table_model.getValueAt(model_row, 0)) - 1
            
            if 0 <= action_index < len(self._actions):
                action = self._actions[action_index]
                self._current_message = action['messageInfo']
                self._current_action_id = action['action_id']
                
                # Update viewers
                self._request_viewer.setMessage(action['messageInfo'].getRequest(), True)
                self._response_viewer.setMessage(action['messageInfo'].getResponse(), False)
                
                # Update notes area with current action's notes
                self._notes_area.setText(self._action_notes.get(self._current_action_id, ""))
    
    def save_notes(self, event):
        """Save notes for the current action"""
        if self._current_action_id:
            notes = self._notes_area.getText()
            
            # Update notes for this action ID
            self._action_notes[self._current_action_id] = notes
            
            # Update all rows with this action ID
            with self._lock:
                for i in range(self._table_model.getRowCount()):
                    table_action_id = self._table_model.getValueAt(i, 3)
                    # Handle both full and truncated action IDs
                    if table_action_id == self._current_action_id or table_action_id.startswith(self._current_action_id[:20]):
                        self._table_model.setValueAt(notes, i, 10)
                
                for a in self._actions:
                    if a['action_id'] == self._current_action_id:
                        a['action_notes'] = notes
            
            print("Notes saved for action: " + self._current_action_id)
    
    def clear_table(self, event):
        with self._lock:
            self._table_model.setRowCount(0)
            self._actions = []
            self._action_map = {}
            self._current_action_id = None
            self._stats['total_actions'] = 0
            self._stats['unique_actions'].clear()
        print("Table cleared")
    
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
        
        # Use proper parent frame
        parent_frame = self._burp_frame if self._burp_frame else self._main_panel
        
        result = JOptionPane.showConfirmDialog(
            parent_frame,
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
                'total_requests': self._stats['total_actions'],
                'unique_actions': len(self._stats['unique_actions']),
                'total_discovered': len(self._all_discovered_actions),
                'include_executed': include_executed.isSelected(),
                'include_unused': include_unused.isSelected(),
                'include_security': include_security.isSelected(),
                'include_full_details': include_full_details.isSelected()
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
                
                # Check for security issues in usages
                for usage in usages:
                    security_notes = usage['security_notes']
                    if security_notes:
                        if 'No auth headers' in security_notes:
                            export_data['security_findings']['unauthenticated_actions'].append(action_id)
                            break
                        if any(term in security_notes for term in ['password', 'token', 'secret', 'credit']):
                            export_data['security_findings']['sensitive_param_actions'].append(action_id)
                            break
                        if 'Error in response' in security_notes or 'DB error exposed' in security_notes:
                            export_data['security_findings']['error_leaking_actions'].append(action_id)
                            break
                
                # Check for frequently reused actions
                if len(usages) > 10:
                    export_data['security_findings']['frequently_reused_actions'].append({
                        'action_id': action_id,
                        'function_name': self._action_names.get(action_id, "Unknown"),
                        'usage_count': len(usages)
                    })
            
            # Deduplicate lists
            for key in ['unauthenticated_actions', 'sensitive_param_actions', 'error_leaking_actions']:
                export_data['security_findings'][key] = list(set(export_data['security_findings'][key]))
        
        # File chooser
        chooser = JFileChooser()
        chooser.setFileFilter(FileNameExtensionFilter("JSON files", ["json"]))
        
        # Set default filename with timestamp
        default_name = "nextjs_actions_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
        chooser.setSelectedFile(java.io.File(default_name))
        
        if chooser.showSaveDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            
            # Add .json extension if not present
            if not file_path.endswith('.json'):
                file_path += '.json'
            
            try:
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                JOptionPane.showMessageDialog(
                    parent_frame,
                    "Export saved successfully to:\n" + file_path,
                    "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE
                )
                print("Export saved to: " + file_path)
            except Exception as e:
                JOptionPane.showMessageDialog(
                    parent_frame,
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
        """Send to Intruder with parameter positions marked"""
        selected_row = self._actions_table.getSelectedRow()
        if selected_row >= 0:
            model_row = self._actions_table.convertRowIndexToModel(selected_row)
            action_index = int(self._table_model.getValueAt(model_row, 0)) - 1
            
            if 0 <= action_index < len(self._actions):
                action = self._actions[action_index]
                messageInfo = action['messageInfo']
                
                # Get request as string
                request = self._helpers.bytesToString(messageInfo.getRequest())
                
                # Find and mark JSON parameters
                body_start = request.find("\r\n\r\n")
                if body_start != -1:
                    body = request[body_start+4:]
                    
                    try:
                        # Parse JSON to find value positions
                        data = json.loads(body)
                        if isinstance(data, list) and len(data) > 1:
                            # Create modified body with Intruder position markers
                            modified_body = body
                            
                            # Mark each parameter value
                            # Note: This is simplified - real implementation would need proper position tracking
                            for i, param in enumerate(data[1:], 1):
                                if isinstance(param, dict):
                                    for key, value in param.items():
                                        # Find the value in the body and mark it
                                        value_str = json.dumps(value)
                                        marked_value = "§" + value_str.strip('"') + "§"
                                        modified_body = modified_body.replace(value_str, marked_value, 1)
                            
                            # Reconstruct request
                            modified_request = request[:body_start+4] + modified_body
                            
                            self._callbacks.sendToIntruder(
                                messageInfo.getHttpService().getHost(),
                                messageInfo.getHttpService().getPort(),
                                messageInfo.getHttpService().getProtocol() == "https",
                                self._helpers.stringToBytes(modified_request)
                            )
                            return
                    except:
                        pass
                
                # Fallback to regular send
                self.send_to_intruder()
    
    def getHttpService(self):
        return self._current_message.getHttpService() if hasattr(self, '_current_message') else None
    
    def getRequest(self):
        return self._current_message.getRequest() if hasattr(self, '_current_message') else None
    
    def getResponse(self):
        return self._current_message.getResponse() if hasattr(self, '_current_message') else None
    
    def find_function_in_responses(self, action_id, function_name):
        """Search through stored chunk responses to find where this function/action is defined"""
        for chunk_data in self._chunk_responses:
            if action_id in chunk_data['body'] or function_name in chunk_data['body']:
                return chunk_data['message']
        return None
    
    def create_repeater_request_for_action(self, action_id, function_name):
        """Create a Repeater tab for testing a discovered but unused action"""
        # First check if we have the action in our discovered list
        if action_id in self._all_discovered_actions:
            info = self._all_discovered_actions[action_id]
            
            # Try to find the chunk where this action is defined
            chunk_message = self.find_function_in_responses(action_id, function_name)
            if chunk_message:
                self._callbacks.sendToRepeater(
                    chunk_message.getHttpService().getHost(),
                    chunk_message.getHttpService().getPort(),
                    chunk_message.getHttpService().getProtocol() == "https",
                    chunk_message.getRequest(),
                    "Chunk with " + function_name
                )
            
            # Also try to find a recent Server Action request to use as template
            recent_action = None
            if self._actions:
                recent_action = self._actions[-1]  # Get most recent action
            
            if recent_action:
                # Create a modified request with the unused action ID
                template_request = recent_action['messageInfo'].getRequest()
                template_service = recent_action['messageInfo'].getHttpService()
                
                # Look for any executed request to use as template
                if not template_request and self._actions:
                    # Find any action with a valid request
                    for action in self._actions:
                        if action['messageInfo'] and action['messageInfo'].getRequest():
                            template_request = action['messageInfo'].getRequest()
                            template_service = action['messageInfo'].getHttpService()
                            break
                
                # If we still don't have a template, try proxy history
                if not template_request:
                    proxy_history = self._callbacks.getProxyHistory()
                    for message in proxy_history[-100:]:  # Check last 100 requests
                        request_info = self._helpers.analyzeRequest(message)
                        headers = request_info.getHeaders()
                        for header in headers:
                            if header.lower().startswith("next-action:"):
                                template_request = message.getRequest()
                                template_service = message.getHttpService()
                                break
                        if template_request:
                            break
                
                if template_request and template_service:
                    # Modify the request to use the unused action ID
                    request_str = self._helpers.bytesToString(template_request)
                    request_info = self._helpers.analyzeRequest(template_service, template_request)
                    
                    # Replace the action ID in headers
                    headers = request_info.getHeaders()
                    new_headers = []
                    for header in headers:
                        if header.lower().startswith("next-action:"):
                            new_headers.append("Next-Action: " + action_id)
                        else:
                            new_headers.append(header)
                    
                    # Replace action ID in body if present
                    body_offset = request_info.getBodyOffset()
                    body = request_str[body_offset:]
                    
                    try:
                        data = json.loads(body)
                        if isinstance(data, list) and len(data) > 0:
                            data[0] = action_id
                            body = json.dumps(data)
                    except:
                        pass
                    
                    # Reconstruct request
                    new_request = "\r\n".join(new_headers) + "\r\n\r\n" + body
                    
                    # Send to Repeater
                    self._callbacks.sendToRepeater(
                        template_service.getHost(),
                        template_service.getPort(),
                        template_service.getProtocol() == "https",
                        self._helpers.stringToBytes(new_request),
                        "Test: " + function_name + " (unused)"
                    )
                    
                    print("Created Repeater tab for testing unused action: " + function_name)
                    return True
        
        return False

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
        
        # Get the row at the mouse position
        table = event.getSource()
        row = table.rowAtPoint(event.getPoint())
        
        if row >= 0:
            # Select the row
            table.setRowSelectionInterval(row, row)
            
            # Create popup menu
            popup = JPopupMenu()
            
            # Add menu items
            send_repeater = JMenuItem("Send to Repeater", actionPerformed=lambda e: self.extender.send_to_repeater())
            send_intruder = JMenuItem("Send to Intruder", actionPerformed=lambda e: self.extender.send_to_intruder())
            send_intruder_fuzz = JMenuItem("Send to Intruder (Mark Parameters)", actionPerformed=lambda e: self.extender.send_to_intruder_with_positions())
            
            popup.add(send_repeater)
            popup.add(send_intruder)
            popup.add(send_intruder_fuzz)
            
            # Add separator
            popup.addSeparator()
            
            # Add copy action ID option
            copy_action = JMenuItem("Copy Action ID", actionPerformed=lambda e: self.copy_action_id(row))
            popup.add(copy_action)
            
            # Add lookup action
            lookup_action = JMenuItem("Lookup Server Action", actionPerformed=lambda e: self.lookup_server_action(row))
            popup.add(lookup_action)
            
            # Show popup
            popup.show(event.getComponent(), event.getX(), event.getY())
    
    def copy_action_id(self, row):
        """Copy action ID to clipboard"""
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        
        model_row = self.extender._actions_table.convertRowIndexToModel(row)
        action_index = int(self.extender._table_model.getValueAt(model_row, 0)) - 1
        
        if 0 <= action_index < len(self.extender._actions):
            action_id = self.extender._actions[action_index]['action_id']
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(action_id), None)
            print("Copied action ID: " + action_id)
    
    def lookup_server_action(self, row):
        """Lookup server action details"""
        model_row = self.extender._actions_table.convertRowIndexToModel(row)
        action_index = int(self.extender._table_model.getValueAt(model_row, 0)) - 1
        
        if 0 <= action_index < len(self.extender._actions):
            action = self.extender._actions[action_index]
            action_id = action['action_id']
            
            print("\n=== Server Action Details ===")
            print("Action ID: " + action_id)
            
            if action_id in self.extender._action_names:
                print("Function Name: " + self.extender._action_names[action_id])
            
            if action_id in self.extender._all_discovered_actions:
                info = self.extender._all_discovered_actions[action_id]
                print("Chunk File: " + info.get('chunk_file', 'Unknown'))
                print("First Discovered: " + info.get('first_seen', 'Unknown'))
            
            # Count executions
            exec_count = sum(1 for a in self.extender._actions if a['action_id'] == action_id)
            print("Total Executions: " + str(exec_count))
            
            # Show unique URLs
            urls = set(a['url'] for a in self.extender._actions if a['action_id'] == action_id)
            print("Unique URLs: " + str(len(urls)))
            for url in list(urls)[:5]:
                print("  - " + url)
            
            # Show parameters
            all_params = set()
            for a in self.extender._actions:
                if a['action_id'] == action_id:
                    all_params.update(a['params'])
            
            if all_params:
                print("Parameters seen: " + ", ".join(all_params))
            
            # Security issues
            security_issues = set()
            for a in self.extender._actions:
                if a['action_id'] == action_id and a['security_notes']:
                    security_issues.update(a['security_notes'].split(', '))
            
            if security_issues:
                print("Security Issues: " + ", ".join(security_issues))

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
        
        # Get the row at the mouse position
        row = self.table.rowAtPoint(event.getPoint())
        
        if row >= 0:
            # Select the row
            self.table.setRowSelectionInterval(row, row)
            
            # Get the action ID and function name from the selected row
            model = self.table.getModel()
            action_id_short = model.getValueAt(row, 0)  # This is shortened
            function_name = model.getValueAt(row, 1)
            
            # Find the full action ID
            full_action_id = None
            for aid, info in self.extender._all_discovered_actions.items():
                if aid.startswith(action_id_short.replace("...", "")) and info['function_name'] == function_name:
                    full_action_id = aid
                    break
            
            if not full_action_id:
                # Try to find in executed actions
                for action in self.extender._actions:
                    if action['action_id'].startswith(action_id_short.replace("...", "")):
                        full_action_id = action['action_id']
                        break
            
            # Create popup menu
            popup = JPopupMenu()
            
            # Add menu items
            if full_action_id:
                copy_action = JMenuItem("Copy Action ID", actionPerformed=lambda e: self.copy_action_id(full_action_id))
                popup.add(copy_action)
            
            copy_function = JMenuItem("Copy Function Name", actionPerformed=lambda e: self.copy_function_name(function_name))
            popup.add(copy_function)
            
            # If this is an unused action, add option to create test request
            status = model.getValueAt(row, 2)
            if "Unused" in status or "Never" in status:
                popup.addSeparator()
                create_test = JMenuItem("Create Test Request in Repeater", 
                                       actionPerformed=lambda e: self.extender.create_repeater_request_for_action(full_action_id, function_name))
                popup.add(create_test)
            
            # Show popup
            popup.show(event.getComponent(), event.getX(), event.getY())
    
    def copy_action_id(self, action_id):
        """Copy full action ID to clipboard"""
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(action_id), None)
        print("Copied action ID: " + action_id)
    
    def copy_function_name(self, function_name):
        """Copy function name to clipboard"""
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(function_name), None)
        print("Copied function name: " + function_name)