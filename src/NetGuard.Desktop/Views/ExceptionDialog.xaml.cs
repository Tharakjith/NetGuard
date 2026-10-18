using System.Windows;

namespace NetGuard.Desktop.Views;

public partial class ExceptionDialog : Window
{
    private ExceptionDialog(string applicationName)
    {
        InitializeComponent();
        Intro.Text = $"Allow {applicationName} to use the network for a limited time. The restriction is re-applied automatically when the time is up, even after a restart.";
        Duration.ItemsSource = new[]
        {
            new DurationOption(15, "15 minutes"),
            new DurationOption(30, "30 minutes"),
            new DurationOption(60, "1 hour"),
            new DurationOption(120, "2 hours"),
            new DurationOption(240, "4 hours"),
            new DurationOption(480, "8 hours"),
            new DurationOption(1440, "24 hours"),
        };
        Loaded += (_, _) => Reason.Focus();
    }

    public static (int Minutes, string Reason)? Ask(string applicationName)
    {
        var dialog = new ExceptionDialog(applicationName) { Owner = Application.Current.MainWindow };
        return dialog.ShowDialog() == true && dialog.Duration.SelectedItem is DurationOption option
            ? (option.Minutes, dialog.Reason.Text.Trim())
            : null;
    }

    private void OnGrant(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(Reason.Text))
        {
            Error.Text = "Enter a reason. It is recorded in the audit log with your account name.";
            return;
        }

        DialogResult = true;
    }

    private sealed record DurationOption(int Minutes, string Label);
}
