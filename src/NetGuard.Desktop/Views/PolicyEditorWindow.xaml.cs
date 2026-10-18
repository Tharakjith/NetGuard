using System.Windows;
using NetGuard.Desktop.ViewModels;

namespace NetGuard.Desktop.Views;

public partial class PolicyEditorWindow : Window
{
    private PolicyEditorWindow(PolicyEditorViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.Close = saved => DialogResult = saved;
    }

    /// <summary>Shows the editor modally. Returns the service's response when saved, otherwise null.</summary>
    public static object? ShowEditor(PolicyEditorViewModel viewModel)
    {
        var window = new PolicyEditorWindow(viewModel) { Owner = Application.Current.MainWindow };
        return window.ShowDialog() == true ? viewModel.Result : null;
    }
}
