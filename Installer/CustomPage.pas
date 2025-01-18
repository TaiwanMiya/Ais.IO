var
  CustomPage: TWizardPage;
  MyLabel: TLabel;
  MyEdit: TEdit;
  MyCheckBox: TCheckBox;

procedure InitializeWizard();
begin
  // Create a custom page with the title "Custom Page" and the description "Enter Custom Information"
  CustomPage := CreateCustomPage(wpWelcome, 'Custom Page', 'Please enter a custom message');

  // Add tags to custom pages
  MyLabel := TLabel.Create(WizardForm);
  MyLabel.Parent := CustomPage.Surface;
  MyLabel.Caption := 'Please enter some text:';
  MyLabel.Top := 10;
  MyLabel.Left := 10;

  // Add text boxes to custom pages
  MyEdit := TEdit.Create(WizardForm);
  MyEdit.Parent := CustomPage.Surface;
  MyEdit.Top := MyLabel.Top + 30;
  MyEdit.Left := 10;
  MyEdit.Width := 400;

  // Add checkboxes to custom pages
  MyCheckBox := TCheckBox.Create(WizardForm);
  MyCheckBox.Parent := CustomPage.Surface;
  MyCheckBox.Caption := 'Agree to the terms';
  MyCheckBox.Top := MyEdit.Top + 40;
  MyCheckBox.Left := 10;
end;

// Fired when the next button is clicked to perform some custom validation or action
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  // If the current page is a customized page
  if CurPageID = CustomPage.ID then
  begin
    // Check if text has been entered
    if MyEdit.Text = '' then
    begin
      MsgBox('Please enter some text!', mbError, MB_OK);
      Result := False; // Prevent continuation
      Exit;
    end;

    // Check if "Agree to Terms" is selected
    if not MyCheckBox.Checked then
    begin
      MsgBox('Please Agree to the terms!', mbError, MB_OK);
      Result := False; // Prevent continuation
      Exit;
    end;
  end;

  Result := True; // Allowed to continue
end;


// [Code]
// var
//   CustomPage: TWizardPage;
//   MyLabel: TLabel;
//   MyEdit: TEdit;
//   MyCheckBox: TCheckBox;

// procedure InitializeWizard();
// begin
//   CustomPage := CreateCustomPage(wpWelcome, 'Custom Page', 'Please enter a custom message');

//   MyLabel := TLabel.Create(WizardForm);
//   MyLabel.Parent := CustomPage.Surface;
//   MyLabel.Caption := 'Please enter some text:';
//   MyLabel.Top := 10;
//   MyLabel.Left := 10;

//   MyEdit := TEdit.Create(WizardForm);
//   MyEdit.Parent := CustomPage.Surface;
//   MyEdit.Top := MyLabel.Top + 30;
//   MyEdit.Left := 10;
//   MyEdit.Width := 400;

//   MyCheckBox := TCheckBox.Create(WizardForm);
//   MyCheckBox.Parent := CustomPage.Surface;
//   MyCheckBox.Caption := 'Agree to the terms';
//   MyCheckBox.Top := MyEdit.Top + 40;
//   MyCheckBox.Left := 10;
// end;

// function NextButtonClick(CurPageID: Integer): Boolean;
// begin

//   if CurPageID = CustomPage.ID then
//   begin

//     if MyEdit.Text = '' then
//     begin
//       MsgBox('Please enter some text!', mbError, MB_OK);
//       Result := False;
//       Exit;
//     end;

//     if not MyCheckBox.Checked then
//     begin
//       MsgBox('Please Agree to the terms!', mbError, MB_OK);
//       Result := False;
//       Exit;
//     end;
//   end;

//   Result := True;
// end;