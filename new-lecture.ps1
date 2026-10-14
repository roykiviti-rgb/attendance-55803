# חלון להפקת קודי נוכחות להרצאה. מופעל מהקובץ "הפקת קודים להרצאה.bat".
# בוחרים תאריך ומספר קודים, והסקריפט מריץ את generate.py ופותח את ה-PDF.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$generate = Join-Path $here "generate.py"

$font = New-Object System.Drawing.Font("Segoe UI", 11)

$form = New-Object System.Windows.Forms.Form
$form.Text = "הפקת קודי נוכחות — יסודות המימון"
$form.RightToLeft = "Yes"
$form.RightToLeftLayout = $true
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.ClientSize = New-Object System.Drawing.Size(380, 210)
$form.Font = $font

$lblDate = New-Object System.Windows.Forms.Label
$lblDate.Text = "תאריך ההרצאה:"
$lblDate.Location = New-Object System.Drawing.Point(20, 25)
$lblDate.AutoSize = $true
$form.Controls.Add($lblDate)

$picker = New-Object System.Windows.Forms.DateTimePicker
$picker.Format = "Custom"
$picker.CustomFormat = "dd/MM/yyyy"
$picker.Value = Get-Date
$picker.Location = New-Object System.Drawing.Point(170, 21)
$picker.Width = 180
$form.Controls.Add($picker)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Text = "מספר קודים:"
$lblCount.Location = New-Object System.Drawing.Point(20, 75)
$lblCount.AutoSize = $true
$form.Controls.Add($lblCount)

$count = New-Object System.Windows.Forms.NumericUpDown
$count.Minimum = 1
$count.Maximum = 200
$count.Value = 17
$count.Location = New-Object System.Drawing.Point(170, 71)
$count.Width = 80
$form.Controls.Add($count)

$note = New-Object System.Windows.Forms.Label
$note.Text = "הקודים בתוקף 24 שעות מרגע ההפקה."
$note.ForeColor = [System.Drawing.Color]::DimGray
$note.Location = New-Object System.Drawing.Point(20, 115)
$note.AutoSize = $true
$form.Controls.Add($note)

$ok = New-Object System.Windows.Forms.Button
$ok.Text = "צור קודים"
$ok.Location = New-Object System.Drawing.Point(20, 155)
$ok.Size = New-Object System.Drawing.Size(150, 38)
$ok.DialogResult = "OK"
$form.Controls.Add($ok)
$form.AcceptButton = $ok

$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = "ביטול"
$cancel.Location = New-Object System.Drawing.Point(185, 155)
$cancel.Size = New-Object System.Drawing.Size(100, 38)
$cancel.DialogResult = "Cancel"
$form.Controls.Add($cancel)
$form.CancelButton = $cancel

function Show-Message($text, $icon) {
    $opts = [System.Windows.Forms.MessageBoxOptions]::RightAlign -bor [System.Windows.Forms.MessageBoxOptions]::RtlReading
    [System.Windows.Forms.MessageBox]::Show($text, "הפקת קודי נוכחות", "OK", $icon, "Button1", $opts) | Out-Null
}

if ($form.ShowDialog() -ne "OK") { exit }

$date = $picker.Value.ToString("yyyy-MM-dd")
$pdf = Join-Path $here "out\attendance-55803-$date.pdf"

if (Test-Path $pdf) {
    $opts = [System.Windows.Forms.MessageBoxOptions]::RightAlign -bor [System.Windows.Forms.MessageBoxOptions]::RtlReading
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "כבר הופקו קודים לתאריך $($picker.Value.ToString('dd/MM/yyyy')).`n`nלהפיק קודים חדשים? הקובץ הקיים יוחלף. קודים שכבר הודפסו ימשיכו לעבוד עד שיפוג תוקפם.",
        "הפקת קודי נוכחות", "YesNo", "Question", "Button2", $opts)
    if ($answer -ne "Yes") { exit }
}

# Python: מעדיפים את ה-launcher של Windows (py), ואם אין — python
$python = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }

$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$output = & $python $generate --date $date -n ([int]$count.Value) 2>&1 | Out-String

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $pdf)) {
    if ($output -match "PermissionError") {
        $output = "קובץ ה-PDF של התאריך הזה פתוח בתוכנה אחרת. סגרו אותו ונסו שוב."
    }
    Show-Message "ההפקה נכשלה:`n`n$output" "Error"
    exit 1
}

Start-Process $pdf
