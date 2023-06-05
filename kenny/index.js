// Scroll Smooth
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();

        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Scroll reveal
window.sr = ScrollReveal()
// Navbar
sr.reveal(".navbar", {
    duration: 1000,
    origin: "bottom",
    reset: true
})

// Home
sr.reveal("#home-content", {
    duration: 1000,
    delay: 500,
    origin: "right",
    reset: false
})

sr.reveal("#item1", {
    duration: 1000,
    delay: 750,
    origin: "right",
    distance: "500px",
    reset: false
})
sr.reveal("#item2", {
    duration: 1000,
    delay: 800,
    origin: "right",
    distance: "500px",
    reset: false
})
sr.reveal("#item3", {
    duration: 1000,
    delay: 850,
    origin: "right",
    distance: "500px",
    reset: false
})

//Info
sr.reveal("#info", {
    duration: 1000,
    origin: "left",
    delay: 300,
    distance: "200px",
    reset: true
})

// s3
sr.reveal("#carousel-txt-1", {
    duration: 1000,
    delay: 250,
    origin: "bottom",
    distance: "100px",
    reset: false
})

// s4
sr.reveal("#s4-content-right", {
    duration: 1000,
    origin: "bottom",
    distance: "100px",
    // delay: 200,
    reset: true
})

sr.reveal("#mapakenny", {
    duration: 1000,
    origin: "bottom",
    distance: "100px",
    // delay: 200,
    reset: true
})