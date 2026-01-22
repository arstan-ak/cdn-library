// my-library.js

// Define your functionality
function myLibraryFunction(message) {
    console.log("My Library says: " + message);
}

function anotherFunction() {
    return "This is another function.";
}

// Expose functions to the global window object
window.myLibrary = {
    log: myLibraryFunction,
    getAnother: anotherFunction
};
