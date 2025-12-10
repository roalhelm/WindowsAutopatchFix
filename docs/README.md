# Windows Autopatch - GitHub Pages Setup

This directory contains the GitHub Pages website for Windows Autopatch technical documentation.

## 📁 Structure

```
docs/
├── index.html          # Main documentation page
└── images/             # Diagram and screenshot directory
    ├── quality-update-flow.png      (add your diagram)
    └── feature-update-flow.png      (add your diagram)
```

## 🚀 Activation

To activate GitHub Pages:

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Pages**
3. Under **Source**, select:
   - Branch: `main`
   - Folder: `/docs`
4. Click **Save**
5. Your site will be published at: `https://roalhelm.github.io/WindowsUpdateFix/`

## 🖼️ Adding Images

1. Place your diagram images in the `docs/images/` folder
2. Update `index.html` to reference your images:

```html
<!-- Replace diagram placeholders with: -->
<img src="images/quality-update-flow.png" alt="Quality Update Flow" style="max-width: 100%; height: auto;">
```

### Recommended Images to Add:

- **quality-update-flow.png** - Quality update process diagram
- **feature-update-flow.png** - Feature update process diagram
- **autopatch-rings.png** - Ring deployment visualization
- **error-handling.png** - Error flow diagram
- **components-architecture.png** - System components overview

## 🎨 Customization

The website uses:
- **Responsive Design** - Works on mobile, tablet, desktop
- **Microsoft Colors** - Azure blue theme (#0078d4)
- **Clean Layout** - Professional documentation style
- **Easy Navigation** - Jump links to sections

### Modify Colors:

Edit the CSS in `index.html`:
```css
/* Primary color */
background: #0078d4;  /* Change to your color */
```

## 📊 Features

✅ Fully responsive design
✅ Professional Microsoft-style theme
✅ Component cards with hover effects
✅ Error handling documentation
✅ Reference links to official docs
✅ Easy to add images
✅ Mobile-friendly navigation

## 🔗 Links

- **Live Site:** https://roalhelm.github.io/WindowsUpdateFix/
- **Repository:** https://github.com/roalhelm/WindowsUpdateFix
- **Issues:** https://github.com/roalhelm/WindowsUpdateFix/issues
