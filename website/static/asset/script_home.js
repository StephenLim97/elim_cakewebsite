document.addEventListener('DOMContentLoaded', () => {
    const features = document.querySelectorAll('.featured');

    features.forEach(feature => {
        feature.addEventListener('click', () => {
            features.forEach(f => f.classList.remove('selected')); // Remove 'selected' class from all features
            feature.classList.add('selected'); // Add 'selected' class to the clicked feature
        });
    });
});