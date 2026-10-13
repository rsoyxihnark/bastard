# Changelog

## 1.7.0

- Bastard 1.7.0 hides a source with a click in the panel on the left, and the two filter rows above the list are gone.
- The SOURCE and KIND rows above the list are gone, so the list and the details below have that space back.
- Clicking a source in the panel on the left hides its events, and clicking it again brings them back.
- A source left hidden stays hidden the next time Bastard starts, and the panel says beside it that it is hidden.
- Esc closes the Filter window and the Options window without saving.
- The Processes list no longer fills up with the helpers Bastard starts for its own checks.

## 1.6.3

- Bastard 1.6.3 reads who may change the desktop without starting PowerShell, and leaves out the rows that say nothing.
- Fixed the rights on Control Panel Desktop being read by starting PowerShell, which wrote four values of its own.
- Reading those rights is now a plain read, so a trace is a second quicker and 9000 events lighter.
- The rows ProcMon writes for opening, closing, asking after and listing a registry key are left out by default.
- A denied registry open still shows, and so does every value that was written, read or created.
- ProcMon no longer lists what Bastard and the tools it starts were doing, and the summary says how many it left out.
- The colour rule now names the path the rows actually carry, so the colour reads are left out again.

## 1.6.2

- Bastard 1.6.2 leaves every row about Bastard itself out of the timeline, whichever source reported it.
- The filter now leaves out every event naming Bastard, so the PowerShell it starts for its own checks is gone.

## 1.6.0

- Bastard 1.6.0 keeps the trace log inside its limit on Windows, adds a Clear button, and leaves its own rows out.
- Fixed the trace log growing past the limit it was given whenever it ran on Windows.
- The Clear button between Filter and Options empties the event list, and the log on disk still holds everything.
- The filter now starts with the ProcMon and ETW rows about Bastard itself left out.

## 1.5.4

- Bastard 1.5.4 keeps the trace log small enough to attach, and leaves the Chrome rows out of the timeline.
- The trace log now stops at 28 MB, so a finished log fits under a 30 MB upload limit with room to spare.
- The filter now starts with every ProcMon row from chrome.exe left out.

## 1.5.3

- Bastard 1.5.3 keeps the Kernel-File writes and the refused file operations, and leaves only the reads out.
- The filter now leaves out the ETW Kernel-File reads alone, so a refused write to the wallpaper file still shows.

## 1.5.2

- Bastard 1.5.2 stops the event list moving on its own once a trace has ended, and leaves the Kernel-File events out.
- Fixed the event list shuffling its rows around for as long as the window stayed open after a trace had ended.
- A source that has not let go when a trace ends can no longer add to the list, and the status line says how many it tried.
- The filter now starts with every ETW Kernel-File event left out, which is the loudest thing a trace records.

## 1.5.1

- Bastard 1.5.1 leaves out an event when the filter word sits in its detail lines instead of in the line itself.
- Fixed a rule naming a word like Certificates not leaving out the long Kernel-File events that hold it.
- A filter rule reads an event's detail lines too now, so a word anywhere in the event is enough to leave it out.

## 1.5.0

- Bastard 1.5.0 can leave a whole process out of the timeline, from the right-click menu or by naming it in a rule.
- Right-clicking an event now offers Leave this process out, which keeps every line from that process out of the way.
- A filter rule reads the process name as well as the event text, so a rule can name a process instead of a line.
- Fixed right-clicking a ProcMon event offering to leave out only that one line instead of the process behind it.

## 1.4.2

- Bastard 1.4.2 closes ProcMon the quick way first, so the finish is no longer held up at the end of a trace.
- Fixed the finish taking longer than it used to, because closing ProcMon started a second copy of ProcMon.
- ProcMon is closed the plain way first now, and only asked to stop through its own command when that is ignored.

## 1.4.1

- Bastard 1.4.1 keeps the trace log under the limit it was given, and lets the ProcMon row count be set.
- Fixed the trace log growing past its limit, because the limit counted letters while the log is written in bytes.
- The log limit now leaves room for the lines written at the end, so a 30 MB limit gives a file under 30 MB.
- Options now carries how many ProcMon rows one trace may list, which is what decides how long the finish takes.
- ProcMon is now asked to stop the way it is meant to be, instead of the trace waiting up to 45 seconds for it.
- Reading the capture stops once the ProcMon row count is reached, rather than reading every row and listing none.
- While ProcMon is closing, the panel counts down the seconds the trace is still waiting for it.

## 1.4.0

- Bastard 1.4.0 sorts the timeline by any column, and starts the filter with three rules instead of the old ones.
- Clicking a column heading sorts the listed events by it, and clicking the same heading again turns the order around.
- The heading shows which column the sort is on and which way it runs, and the choice is kept for the next trace.
- Clicking Time puts the timeline back in the order the events arrived.
- The filter now starts with one ProcMon colour read, and with every line that holds DisallowRun or Certificates.
- The rules that used to leave out the ETW handle events and every ProcMon read are gone, so those show again.

## 1.3.2

- Bastard 1.3.2 never writes anything outside its own files: the one write test it still had is gone.
- The TranscodedWallpaper probe no longer opens the file to write, and reports its size, last write and rights instead.
- Who may change the desktop key is read with Get-Acl now, because icacls cannot read a registry path at all.
- Nothing in Bastard touches a registry value, a setting or a file of Windows any more, in any way.

## 1.3.1

- Bastard 1.3.1 keeps an empty filter empty, and lets logman and WPR sleep while the ETW source is reading.
- Deleting every rule in the filter now lasts: the list no longer fills itself with the defaults at the next start.
- logman and WPR only capture when the ETW source cannot read, since they record the same providers it does.
- A trace with the ETW source live no longer decodes a second capture with tracerpt, which was most of the wait after Stop.
- The filter no longer leaves out what logman and WPR read, so when they are the only trace, all of it shows.

## 1.3.0

- Bastard 1.3.0 leaves the repetitive noise out, keeps its files next to itself, and says what it is doing after Stop.
- A filter list decides what never reaches the timeline or the log, and it starts with the three streams that said least.
- ETW file events that carry only handles are left out, and the ones that name a file are kept.
- The reads ProcMon and Trace Tools list are left out, while every denial and every write they see is kept.
- Right click an event and Leave this match out writes a rule for events shaped like that one.
- The Filter button shows the whole list to read and to edit, and Back to the defaults restores it.
- The rules live in Exclusions.ini next to Bastard, so they last and can be edited without the program.
- The trace log is written next to Bastard now, instead of on the Desktop.
- The Options button sets how large the trace log may grow, 30 MB to begin with, and the log says where it stopped.
- The log holds everything the filter let through rather than every event, so the filter decides its size as well.
- ProcMon, Probes and Trace Tools turn green when they finish, instead of going grey as if they had never run.
- While a trace is finishing, the status line names the sources still reading what they captured.
- Open in ProcMon, Export CSV, Export JSON and Open log folder are gone from the bar, and Ctrl+S and Ctrl+J still export.

## 1.2.3

- Bastard 1.2.3 reads four more personalization policies and reports where the Desktop and AppData folders really are.
- Probes now read the Spotlight policy, which can hold the lock screen and the desktop image.
- Probes now read NoLockScreen and NoChangingLockScreen under the user, next to the machine ones they already read.
- Probes now read NoSaveSettings, which keeps Explorer from saving what the user changes.
- Probes now report the Desktop, AppData, Local AppData and Pictures folders, and warn when one is outside the user profile.
- A redirected Desktop or AppData folder moves the trace log and the theme folders Bastard watches, so it is worth seeing.

## 1.2.2

- Bastard 1.2.2 is the 1.2.1 fixes in a release: 1.2.1 was never published, because the release step stopped at its first check.
- The release step now accepts a merge at the head of a push, and takes the version from the commit that sets it.
- The release step no longer checks a merge commit message, which is made from the branch name rather than written by hand.
- Nothing in the program itself changed since 1.2.1.

## 1.2.1

- Bastard 1.2.1 keeps the quiet sources in the timeline when ETW, ProcMon and Trace Tools flood it.
- The reads from the loud sources can fill at most four fifths of the timeline, so the other events always have room.
- Denials and registry and file writes now keep their place in the timeline, however many reads arrive.
- Before this a flood could fill the timeline, and every later event, markers and Trace stopped included, was only in the log.
- A trace with a million events now finishes in seconds instead of minutes, because the timeline is put in time order when it is read.
- The self-test now reports every quiet event with a sample of each loud stream, instead of the first events by time.
- The log on the Desktop still keeps the whole run, as it did before.

## 1.2.0

- Bastard 1.2.0 lets the whole river through: ETW, ProcMon and Trace Tools now list every event, not only the personalization ones.
- ETW now lists every registry and file event it parses, whatever key or path it touches.
- ProcMon now lists every operation it captures, reads and lookups on every path, not only the personalization ones.
- ProcMon now also lists its network operations, next to the file, registry and process ones.
- Trace Tools now lists every row logman or WPR captured, not only the personalization ones.
- The timeline now holds up to a million events in memory, and the log on the Desktop still keeps the whole run.
- The kind filter has new Network, Trace and Probe buttons, so you can hide or show each stream yourself.
- Bastard still leaves out only its own work and the ProcMon helper, so the trace does not feed on itself.

## 1.1.0

- Bastard 1.1.0 reads every channel the earlier versions read and shows all of it unfiltered, so you can sift the noise yourself.
- ETW follows the Kernel-Registry, Kernel-File, Shell-Core, Immersive-Shell and Themes providers live and lists their events.
- ProcMon now also lists reads and lookups on the wallpaper, theme, Photos and lock screen paths, not only writes and denials.
- ProcMon no longer groups repeats, so every captured operation shows on its own line.
- Registry now also watches the LogonUI background, the ActivatableClasses packages, the Personalization policies and the System policies.
- Files now also watches the Explorer folder under Local AppData and reports every change the moment it arrives.
- Windows now records a line when a window is first created, on top of in front, opened, shown and closed.
- WMI reports new processes and wallpaper value changes the way Windows itself sees them.
- Probes reads the personalization and app privacy policies, the consent store, DisallowRun, image options, services and permissions at start.
- Probes reads the Set as desktop background menu entry, the image file associations and the Photos package name, version and status.
- Probes reads the lock screen image path and whether Windows still reports the wallpaper can be set.
- Trace Tools records the same providers with logman, or WPR when logman will not start, and reads them back with tracerpt.

## 1.0.0

- Bastard 1.0.0 is a monitor: it watches and records what happens on the PC and never changes a setting, an app or Windows.
- Start begins a trace, Marker marks the moment you try something, and Stop ends the trace.
- Every trace shows registry, file, process, window, event log, ProcMon and wallpaper events in one timeline, in time order.
- Registry shows every change under the desktop, wallpaper, lock screen, theme, accent and personalization keys, before and after.
- Registry shows which picture the TranscodedImageCache value points to, instead of raw bytes.
- Files shows files created, changed, renamed or deleted in the Themes folders and the Photos app folder.
- Processes shows every program that starts or exits, with its parent and its command line.
- When Bastard runs as administrator, Processes also catches programs that live only a moment and shows their exit codes.
- Windows shows which window comes to the front and which windows and dialogs open, with the dialog text when it can be read.
- Event Log shows new entries from Application, System and the app, shell and task logs, plus the minute before Start.
- ProcMon records a capture when Procmon64.exe sits next to Bastard, and lists denied access, registry writes and file writes from it.
- ProcMon results appear in the timeline at the moment they happened, and Open in ProcMon opens the whole capture.
- Wallpaper shows the wallpaper Windows reports at Start and every change to it.
- Six seconds after a Marker, the timeline sums up what happened in that time, or says that nothing happened.
- Each trace is written live to a log on the Desktop and put in time order when the trace ends.
- The SOURCE and KIND filters, Show and Search narrow the timeline, and DETAILS shows everything about the selected event.
- Copy puts the selected events on the clipboard, and Export CSV and Export JSON save the events that match the filters.
- Stop never freezes the window: ProcMon results are read in the background while the ProcMon light shows the progress.
- Closing the window during a trace stops every source, ProcMon included.
- When it is not run as administrator, Bastard offers to restart as administrator, which ProcMon and short-lived processes need.
- The window remembers its size, position, divider and filters.
- F5 starts, Shift+F5 stops, F8 places a Marker, Ctrl+F jumps to Search, and Ctrl+S and Ctrl+J export.
